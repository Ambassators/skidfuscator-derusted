package dev.skidfuscator.obfuscator.nativebackend;

import dev.skidfuscator.config.nativeobfuscation.NativeConfig;
import dev.skidfuscator.config.nativeobfuscation.NativeArtifactMode;
import dev.skidfuscator.config.nativeobfuscation.NativeMode;
import dev.skidfuscator.config.nativeobfuscation.NativeTarget;
import dev.skidfuscator.config.nativeobfuscation.NativeToolchainDelivery;
import dev.skidfuscator.nativeir.NativeBackend;
import dev.skidfuscator.nativeir.NativeFunction;
import dev.skidfuscator.nativeir.NativeInstruction;
import dev.skidfuscator.nativeir.NativeModule;
import dev.skidfuscator.nativetoolchain.AuthenticatedToolchainResolvers;
import dev.skidfuscator.nativetoolchain.CanonicalLlvmIrEmitter;
import dev.skidfuscator.nativetoolchain.NativeCompilationRequest;
import dev.skidfuscator.nativetoolchain.NativeCompilationResult;
import dev.skidfuscator.nativetoolchain.NativeStringProtection;
import dev.skidfuscator.nativetoolchain.ProcessNativeCompiler;
import dev.skidfuscator.nativetoolchain.ResolvedToolchain;
import dev.skidfuscator.nativetoolchain.ToolchainDelivery;
import dev.skidfuscator.nativetoolchain.ToolchainManifestUriResolver;
import dev.skidfuscator.nativetoolchain.ToolchainRequest;
import dev.skidfuscator.nativetoolchain.VmProtectionSettings;
import dev.skidfuscator.obfuscator.Skidfuscator;
import dev.skidfuscator.obfuscator.SkidfuscatorSession;
import dev.skidfuscator.obfuscator.nativebackend.artifact.NativeArtifactPackager;
import dev.skidfuscator.obfuscator.nativebackend.artifact.NativeCompilationInstaller;
import dev.skidfuscator.obfuscator.nativebackend.commit.NativeMethodCommitTransaction;
import dev.skidfuscator.obfuscator.nativebackend.directory.NativeToolchainDirectories;
import dev.skidfuscator.obfuscator.nativebackend.key.NativeThreadedKeyRegistry;
import dev.skidfuscator.obfuscator.nativebackend.selection.NativeSelection;
import dev.skidfuscator.obfuscator.nativebackend.selection.NativeSelectionSource;
import dev.skidfuscator.obfuscator.nativebackend.lowering.ConstructorTailAnalyzer;
import dev.skidfuscator.obfuscator.nativebackend.lowering.JavaLinkageBridgeRegistry;
import dev.skidfuscator.obfuscator.nativebackend.lowering.MapleNativeIrLowerer;
import dev.skidfuscator.obfuscator.nativebackend.runtime.NativeLoaderGenerator;
import dev.skidfuscator.obfuscator.nativebackend.runtime.NativeLoaderSpec;
import dev.skidfuscator.obfuscator.skidasm.SkidMethodNode;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Native lifecycle gate. It reserves candidates before structural transforms,
 * revalidates those exact methods at the lowering boundary, and prevents an
 * opt-in native build from silently emitting an unprotected Java jar.
 *
 * <p>The typed IR, verifier, authenticated toolchain resolver, compiler driver,
 * and artifact packager live in their dedicated modules. The MapleIR-to-native
 * lowerer and Java loader/commit transaction are intentionally required before
 * this gate may mutate a method.</p>
 */
public final class NativePipeline {
    static final URI DEFAULT_RELEASE_BASE = URI.create(
            "https://github.com/skidfuscatordev/SkidLLVM/releases/download/");
    private final Skidfuscator skidfuscator;
    private boolean nativeArtifactsInstalled;

    public NativePipeline(final Skidfuscator skidfuscator) {
        this.skidfuscator = Objects.requireNonNull(skidfuscator, "skidfuscator");
    }

    /** Reserves candidates before normal EventBus transformations begin. */
    public NativeCompilationPlan reserve() {
        final NativeConfig config = skidfuscator.getConfig().getNativeConfig();
        config.getThreadedKeyConfig().validate(config.isEnabled());
        if (!config.isEnabled()) {
            return new NativeCompilationPlan(List.of(), List.of());
        }

        validateRequest(config);
        return new NativeCompilationPlanner(config).plan(applicationMethods());
    }

    /** Backward-compatible one-shot entry point used by callers without transform phases. */
    public NativeCompilationPlan prepare() {
        return prepare(reserve());
    }

    /** Revalidates a pre-transform reservation at the native lowering boundary. */
    public NativeCompilationPlan prepare(final NativeCompilationPlan reservation) {
        Objects.requireNonNull(reservation, "reservation");
        final NativeConfig config = skidfuscator.getConfig().getNativeConfig();
        config.getThreadedKeyConfig().validate(config.isEnabled());
        if (!config.isEnabled()) {
            return new NativeCompilationPlan(List.of(), List.of());
        }

        final Request request = validateRequest(config);
        final NativeCompilationPlan plan = new NativeCompilationPlanner(config)
                .revalidate(reservation, applicationMethods());
        for (NativeCompilationPlan.Skipped skipped : plan.skipped()) {
            Skidfuscator.LOGGER.warn(
                    "Native selection skipped " + skipped.selection().getMethod() + ": " + skipped.reason()
            );
        }
        final boolean threadedKeys = config.getThreadedKeyConfig().isEnabled();
        if (threadedKeys && skidfuscator.getNativeThreadedKeys().isEmpty()) {
            throw new NativeSelectionException(
                    "Native threaded-key protection was requested, but no eligible threaded seed sites were generated. "
                            + "Enable interprocedural flow threading and retain eligible internal call edges; "
                            + "no unprotected fallback jar will be written.");
        }
        if (plan.candidates().isEmpty() && !threadedKeys) {
            return plan;
        }

        return execute(plan, request, config);
    }

    private NativeCompilationPlan execute(
            final NativeCompilationPlan plan,
            final Request request,
            final NativeConfig config
    ) {
        final List<NativeCompilationPlan.Skipped> skipped = new ArrayList<>(plan.skipped());
        final List<Lowered> lowered = new ArrayList<>();
        final String random = randomId();
        final JavaLinkageBridgeRegistry linkageBridges = new JavaLinkageBridgeRegistry(
                random, this::isCallerSensitive);
        final MapleNativeIrLowerer lowerer = new MapleNativeIrLowerer(linkageBridges);
        final String moduleName = "skid-native-" + random;
        final NativeStringProtection stringProtection = NativeStringProtection.randomized();
        final CanonicalLlvmIrEmitter llvmEmitter = new CanonicalLlvmIrEmitter(stringProtection);
        final org.objectweb.asm.commons.Remapper remapper = skidfuscator.getClassRemapper() == null
                ? new org.objectweb.asm.commons.Remapper() { }
                : skidfuscator.getClassRemapper();
        final NativeIrFinalNameRemapper finalNameRemapper = new NativeIrFinalNameRemapper(remapper);
        final NativeWrapperPlanner wrapperPlanner = new NativeWrapperPlanner(
                skidfuscator.getJarContents() == null
                        ? new org.topdank.byteengineer.commons.data.JarContents()
                        : skidfuscator.getJarContents(), random, remapper);
        int index = 0;
        for (final NativeCompilationPlan.Candidate candidate : plan.candidates()) {
            final int linkageCheckpoint = linkageBridges.checkpoint();
            try {
                final int ordinal = index;
                final NativeBackend backend = candidate.selection().getMode() == NativeMode.VM
                        ? NativeBackend.VM : NativeBackend.AOT;
                final SkidMethodNode method = candidate.selection().getMethod() instanceof SkidMethodNode skidMethod
                        ? skidMethod : null;
                final org.mapleir.ir.cfg.ControlFlowGraph nativeGraph = method == null ? null
                        : dev.skidfuscator.obfuscator.creator.SkidFlowGraphBuilder.buildNativeSsa(skidfuscator, method);
                final NativeModule single;
                final ConstructorTailAnalyzer.Result constructorPlan;
                if (candidate.selection().getMethod().isInit()) {
                    if (method == null) {
                        throw new IllegalArgumentException("constructor tail lowering requires a finalized MapleIR graph");
                    }
                    constructorPlan = new ConstructorTailAnalyzer().analyze(method, nativeGraph);
                    if (!constructorPlan.supported()) {
                        throw new IllegalArgumentException(constructorPlan.reason());
                    }
                    single = lowerer.lowerConstructorTail(
                            moduleName, "skid_fn_" + random + "_" + index++,
                            wrapperPlanner.helperName(ordinal), method, nativeGraph, constructorPlan, backend);
                } else {
                    constructorPlan = null;
                    final String symbol = "skid_fn_" + random + "_" + index++;
                    single = nativeGraph == null
                            ? lowerer.lower(moduleName, symbol, candidate.selection().getMethod(), backend)
                            : lowerer.lower(moduleName, symbol, method, nativeGraph, backend);
                }
                reserveNativeMemberReferences(single.functions().get(0));
                final NativeFunction remapped = finalNameRemapper.remap(single.functions().get(0));
                reserveNativeMemberReferences(remapped);
                if (candidate.conversion() == NativeEligibility.Conversion.DIRECT) {
                    final boolean javaCopy = candidate.selection().getSource() == NativeSelectionSource.JAVA_COPY;
                    final Lowered prepared = new Lowered(candidate,
                            javaCopy ? NativeEntryPolicy.withEntry(remapped, "copy") : remapped,
                            javaCopy ? new NativeMethodCommitTransaction.JavaCopy(candidate.selection().getMethod())
                                    : new NativeMethodCommitTransaction.Direct(candidate.selection().getMethod()));
                    preflightEmission(moduleName, prepared.function(), llvmEmitter);
                    lowered.add(prepared);
                } else {
                    final NativeWrapperPlanner.Prepared wrapper = constructorPlan == null
                            ? wrapperPlanner.prepare(candidate, remapped, ordinal)
                            : wrapperPlanner.prepareConstructor(candidate, remapped, constructorPlan, ordinal);
                    final Lowered prepared = new Lowered(candidate, wrapper.function(), wrapper.mutation());
                    preflightEmission(moduleName, prepared.function(), llvmEmitter);
                    lowered.add(prepared);
                }
            } catch (RuntimeException failure) {
                linkageBridges.rollback(linkageCheckpoint);
                final String reason = failure instanceof NullPointerException || failure.getMessage() == null
                        ? "descriptor must be ()Ljava/lang/String; or a finalized MapleIR graph is required"
                        : failure.getMessage();
                rejectLowering(candidate, reason, skipped);
            }
        }
        // Generated key helpers are strict candidates, not application-body selections.
        // They have no Java reconstruction body to lower and must never be skipped.
        if (config.getThreadedKeyConfig().isEnabled()) {
            for (final NativeThreadedKeyRegistry.Prepared key : skidfuscator.getNativeThreadedKeys().seal()) {
                final NativeFunction function = finalNameRemapper.remap(key.function());
                preflightEmission(moduleName, function, llvmEmitter);
                skidfuscator.reserveNativeGeneratedClass(function.javaOwner());
                skidfuscator.reserveNativeGeneratedMethod(
                        function.javaOwner(), function.javaName(), function.javaDescriptor());
                skidfuscator.reserveNativeReferencedMember(
                        function.javaOwner(), function.javaName(), function.javaDescriptor());
                final NativeCompilationPlan.Candidate candidate = new NativeCompilationPlan.Candidate(
                        new NativeSelection(key.method(), config.getThreadedKeyConfig().getMode(),
                                NativeSelectionSource.THREADED_KEY, true), NativeEligibility.Conversion.DIRECT);
                lowered.add(new Lowered(candidate, function,
                        new NativeMethodCommitTransaction.Direct(key.method())));
            }
        }
        final String cppBatchMethod = skidfuscator.getConfig().getString("native.cppProtobuf.batchMethod", "");
        final String cppBundle = skidfuscator.getConfig().getString("native.cppProtobuf.bundle", "");
        boolean cppBatchUsed = false;
        if (!cppBatchMethod.isEmpty()) {
            final Lowered batch = lowered.stream().filter(value -> cppBatchMethod.equals(
                    value.function().javaOwner() + "#" + value.function().javaName() + value.function().javaDescriptor()))
                    .findFirst().orElseThrow(() -> new NativeBackendUnavailableException(
                            "Configured C++ protobuf batch method did not successfully lower"));
            if (lowered.stream().anyMatch(value -> CppProtobufRegion.calls(value.function(), batch.function()))) {
                if (cppBundle.isBlank() || !Files.isRegularFile(Path.of(cppBundle)))
                    throw new NativeBackendUnavailableException("Native protobuf caller requires a C++ bundle");
                lowered.replaceAll(value -> value == batch ? new Lowered(value.candidate(),
                        CppProtobufRegion.replace(value.function()), value.mutation()) : value);
                cppBatchUsed = true;
            }
        }
        final boolean cppScannerUsed = skidfuscator.getConfig().getBoolean("native.cppWindowsScanner.enabled", false);
        if (cppScannerUsed) {
            final List<Lowered> scanner = lowered.stream().filter(value ->
                    CppWindowsScannerRegion.OWNER.equals(value.function().javaOwner())).toList();
            if (scanner.size()!=4 || cppBundle.isBlank() || !Files.isRegularFile(Path.of(cppBundle)))
                throw new NativeBackendUnavailableException("C++ scanner requires exactly four lowered facade operations and a bundle");
            lowered.replaceAll(value -> scanner.contains(value) ? new Lowered(value.candidate(),
                    CppWindowsScannerRegion.replace(value.function()),value.mutation()) : value);
        }
        final NativeEntryPolicy.Result entries = NativeEntryPolicy.plan(config,
                lowered.stream().map(value -> new NativeEntryPolicy.Body(value.candidate().selection().getMethod(),
                        value.function(), value.mutation())).toList(), outputMethods(), linkageBridges.generatedHelpers(),
                method -> skidfuscator.getRuntimeContracts() != null
                        && skidfuscator.getRuntimeContracts().isMethodContract(method.node),
                skidfuscator.getClassSource()::findClassNode);
        lowered.removeIf(value -> value.mutation() instanceof NativeMethodCommitTransaction.JavaCopy
                && !entries.liveCopies().contains(NativeEntryPolicy.key(value.function())));
        lowered.replaceAll(value -> entries.removed().contains(value.candidate().selection().getMethod())
                ? new Lowered(value.candidate(), NativeEntryPolicy.withEntry(value.function(), "removed"),
                        new NativeMethodCommitTransaction.Remove(value.candidate().selection().getMethod(),
                        !"true".equals(value.function().metadata().get("java.private")))) : value);
        if (cppScannerUsed && lowered.stream().filter(value -> CppWindowsScannerRegion.OWNER.equals(value.function().javaOwner()))
                .anyMatch(value -> !"removed".equals(value.function().metadata().get("java.entry"))))
            throw new NativeBackendUnavailableException("C++ scanner facade still has a Java entry/contract; cannot elide its owner");
        final NativeFieldPolicy.Result fields = NativeFieldPolicy.plan(config,
                lowered.stream().map(value -> new NativeEntryPolicy.Body(value.candidate().selection().getMethod(),
                        value.function(),value.mutation())).toList(),
                outputMethods().stream().map(method->method.owner).distinct().toList(),
                outputMethods(),linkageBridges.generatedHelpers(),
                field->skidfuscator.getRuntimeContracts()!=null
                        && skidfuscator.getRuntimeContracts().isNativeStorageFieldContract(field),
                skidfuscator.getClassSource()::findClassNode,remapper,
                skidfuscator.getConfig().getStringList("compatibility.exportedPackages",List.of()));
        lowered.replaceAll(value->new Lowered(value.candidate(),fields.rewrite(value.function()),value.mutation()));
        writeLoweringReport(lowered, skipped);
        if (skidfuscator.getConfig().getBoolean("native.analysisOnly", false)) {
            throw new NativeBackendUnavailableException("Native analysis completed: " + lowered.size()
                    + " lowerable, " + skipped.size() + " skipped; analysisOnly requested, no output written");
        }
        if (lowered.isEmpty()) {
            final String rejectionSummary = skipped.stream()
                    .map(value -> value.selection().getMethod() + ": " + value.reason())
                    .collect(Collectors.joining("; "));
            throw new NativeBackendUnavailableException(
                    "None of the " + plan.candidates().size()
                            + " selected method(s) can be lowered by the native backend. "
                            + "No native artifact or modified Java method was committed. Rejections: "
                            + rejectionSummary
            );
        }
        final String buildId = "skid-" + random;
        final String loaderName = "skid/native/Loader_" + random;
        Path workDirectory = null;
        try {
            final java.util.Map<String,String> moduleMetadata = new java.util.HashMap<>();
            moduleMetadata.put("loader", loaderName);
            moduleMetadata.put("registration", "class-local-v1");
            if (cppBatchUsed || cppScannerUsed) moduleMetadata.put("cpp.protobuf.bundle", Path.of(cppBundle).toAbsolutePath().toString());
            final NativeModule module = new NativeModule(moduleName, 1, moduleMetadata);
            lowered.forEach(value -> module.addFunction(value.function()));
            final Set<dev.skidfuscator.nativetoolchain.NativeTarget> targets = toolchainTargets(request.targets());
            final dev.skidfuscator.nativetoolchain.NativeTarget currentHost =
                    dev.skidfuscator.nativetoolchain.NativeTarget.currentHost().orElseThrow(() ->
                            new NativeBackendUnavailableException(
                                    "SkidLLVM is not published for this host operating system/architecture"));
            workDirectory = Files.createTempDirectory("skid-native-" + random + "-");
            final NativeCompilationResult compilation;
            final String compilerDescription;
            if (config.getToolchainConfig().isDevelopmentEnabled()) {
                compilerDescription = "explicit LOCAL DEVELOPMENT SkidLLVM (unsigned, AOT-only)";
                Skidfuscator.LOGGER.warn("Using " + compilerDescription
                        + "; this is not an authenticated release toolchain");
                compilation = new ProcessNativeCompiler(llvmEmitter).compileExplicitLocalAot(
                        module, Path.of(config.getToolchainConfig().getDevelopmentPath()),
                        workDirectory, targets, currentHost, buildId,
                        config.getToolchainConfig().getVersion());
            } else {
                final ResolvedToolchain toolchain = AuthenticatedToolchainResolvers.create(
                        NativeToolchainDirectories.cacheRoot(), NativePipeline.class.getClassLoader(),
                        releaseManifestUris()).resolve(new ToolchainRequest(
                        ToolchainDelivery.valueOf(request.delivery().name()),
                        java.util.Optional.ofNullable(explicitCompiler(config, skidfuscator.getSession())),
                        config.getToolchainConfig().getVersion(), config.getToolchainConfig().getNativeIrAbi(),
                        targets, currentHost));
                compilation = new ProcessNativeCompiler(llvmEmitter)
                        .compile(new NativeCompilationRequest(module, toolchain, workDirectory, targets, currentHost,
                        buildId, vmSettings(config)));
                compilerDescription = "authenticated " + toolchain.source() + " SkidLLVM";
            }
            final NativeLoaderGenerator.GeneratedLoader loader = new NativeLoaderGenerator().generate(
                    NativeLoaderSpec.fromManifest(loaderName, compilation.manifest()));
            skidfuscator.reserveNativeGeneratedClass(loader.internalName());
            linkageBridges.generatedHelpers().forEach(helper ->
                    skidfuscator.reserveNativeGeneratedMethod(
                            helper.owner().getName(), helper.method().name, helper.method().desc));
            final List<NativeMethodCommitTransaction.Mutation> mutations = lowered.stream()
                    .map(Lowered::mutation).toList();
            final List<org.topdank.byteengineer.commons.data.JarClassData> companions =
                    new ArrayList<>(wrapperPlanner.generatedCompanions());
            if (config.getThreadedKeyConfig().isEnabled()) {
                companions.addAll(skidfuscator.getNativeThreadedKeys().generatedCompanions());
            }
            skidfuscator.getJarContents().getClassContents().addAll(companions);
            try {
                new NativeMethodCommitTransaction().commit(
                        skidfuscator.getJarContents(),
                        loader,
                        mutations,
                        linkageBridges.generatedHelpers(),
                        fields.removed().stream().map(f->new NativeMethodCommitTransaction.FieldRemoval(f.owner(),f.node())).toList(),
                        contents -> new NativeCompilationInstaller().install(contents, compilation, targets));
            } catch (IOException | RuntimeException | Error failure) {
                skidfuscator.getJarContents().getClassContents().removeAll(companions);
                throw failure;
            }
            // A committed direct native body keeps its Java calling convention.
            // Record only this explicit implementation transition; the registry
            // continues checking every name, descriptor, and caller-facing flag.
            if (skidfuscator.getRuntimeContracts() != null) {
                for (NativeMethodCommitTransaction.Mutation mutation : mutations) {
                    if (mutation instanceof NativeMethodCommitTransaction.Direct direct) {
                        skidfuscator.getRuntimeContracts()
                                .recordCommittedNativeImplementation(direct.method().node);
                    }
                }
                fields.removed().forEach(f->skidfuscator.getRuntimeContracts().recordCommittedNativeFieldStorage(f.node()));
            }
            nativeArtifactsInstalled = true;
            writeEntryReport(lowered);
            fields.report(skidfuscator.getConfig().getString("native.fields.reportFile",""));
            Skidfuscator.LOGGER.post("Native primitive fields: removed Java declarations="+fields.removed().size());
            Skidfuscator.LOGGER.post("Native Java entries: copies=" + entries.liveCopies().size()
                    + ", removed Java declarations=" + entries.removed().size());
            if (config.getThreadedKeyConfig().isEnabled()) {
                Skidfuscator.LOGGER.post("Native threaded-key protection installed "
                        + skidfuscator.getNativeThreadedKeys().size() + " helper(s) in "
                        + config.getThreadedKeyConfig().getMode() + " mode"
                        + (config.getThreadedKeyConfig().isOnly() ? "; application method bodies remain Java" : ""));
            }
            Skidfuscator.LOGGER.post("Native protection compiled " + lowered.size()
                    + " method(s) for " + targets.size() + " target(s) using "
                    + compilerDescription);
            return new NativeCompilationPlan(
                    lowered.stream().map(Lowered::candidate).toList(), skipped);
        } catch (final InterruptedException exception) {
            Thread.currentThread().interrupt();
            throw new NativeBackendUnavailableException("Native compilation was interrupted", exception);
        } catch (final IOException | RuntimeException exception) {
            throw new NativeBackendUnavailableException(
                    "Native compilation failed before a complete output could be committed: "
                            + exception.getMessage(), exception);
        } finally {
            if (workDirectory != null) {
                if (config.getToolchainConfig().isDevelopmentEnabled()
                        && config.getToolchainConfig().isDevelopmentKeepWorkDirectory()) {
                    Skidfuscator.LOGGER.warn("Retained local native compiler diagnostics: " + workDirectory);
                } else {
                    cleanupTemporaryDirectory(workDirectory);
                }
            }
        }
    }

    private void writeLoweringReport(final List<Lowered> lowered,
                                     final List<NativeCompilationPlan.Skipped> skipped) {
        final String configured = skidfuscator.getConfig().getString("native.reportFile", "");
        if (configured.isBlank()) return;
        final List<String> rows = new ArrayList<>();
        rows.add("status\towner\tmethod\tdescriptor\tmode\treason");
        for (Lowered entry : lowered) {
            var method = entry.candidate().selection().getMethod();
            rows.add("LOWERED\t" + method.owner.getName() + "\t" + method.getName() + "\t"
                    + method.getDesc() + "\t" + entry.function().backend() + "\t");
        }
        for (var entry : skipped) {
            var method = entry.selection().getMethod();
            rows.add("SKIPPED\t" + method.owner.getName() + "\t" + method.getName() + "\t"
                    + method.getDesc() + "\t" + entry.selection().getMode() + "\t"
                    + entry.reason().replace('\t', ' ').replace('\n', ' ').replace('\r', ' '));
        }
        try {
            final Path report = Path.of(configured).toAbsolutePath();
            Files.createDirectories(report.getParent());
            Files.write(report, rows, java.nio.charset.StandardCharsets.UTF_8);
            Skidfuscator.LOGGER.warn("Native lowering report: " + lowered.size() + " lowerable, "
                    + skipped.size() + " skipped (not committed counts): " + report);
        } catch (IOException failure) {
            throw new NativeBackendUnavailableException("Cannot write native lowering report", failure);
        }
    }

    /** Written only after successful compilation and transactional commit. */
    private void writeEntryReport(final List<Lowered> lowered) throws IOException {
        final String configured = skidfuscator.getConfig().getString("native.entryReportFile", "");
        if (configured.isBlank()) return;
        final List<String> rows = new ArrayList<>();
        rows.add("status\towner\tmethod\tdescriptor\tfinalOwner\tfinalMethod\tfinalDescriptor\tentryScope");
        for (Lowered value : lowered) {
            var method = value.candidate().selection().getMethod();
            String status = value.mutation() instanceof NativeMethodCommitTransaction.JavaCopy ? "JAVA_COPY"
                    : value.mutation() instanceof NativeMethodCommitTransaction.Remove ? "NATIVE_ONLY"
                    : value.mutation() instanceof NativeMethodCommitTransaction.Wrapper ? "WRAPPER" : "NATIVE_ENTRY";
            rows.add(status + "\t" + method.owner.getName() + "\t" + method.getName() + "\t" + method.getDesc()
                    + "\t" + value.function().javaOwner() + "\t" + value.function().javaName()
                    + "\t" + value.function().javaDescriptor()
                    + "\t" + value.function().metadata().getOrDefault("java.entryScope", "private"));
        }
        final Path report = Path.of(configured).toAbsolutePath();
        Files.createDirectories(report.getParent());
        Files.write(report, rows, java.nio.charset.StandardCharsets.UTF_8);
    }

    private static void preflightEmission(
            final String moduleName,
            final NativeFunction function,
            final CanonicalLlvmIrEmitter emitter
    ) {
        emitter.emit(new NativeModule(moduleName).addFunction(function));
    }

    private void reserveNativeMemberReferences(final NativeFunction function) {
        function.blocks().stream().flatMap(block -> block.instructions().stream())
                .filter(NativeInstruction.Operation.class::isInstance)
                .map(NativeInstruction.Operation.class::cast)
                .filter(operation -> operation.opcode() == dev.skidfuscator.nativeir.NativeOpcode.JAVA_CALL)
                .forEach(operation -> skidfuscator.reserveNativeReferencedMember(
                        operation.attributes().get("owner"), operation.attributes().get("name"),
                        operation.attributes().get("descriptor")));
    }

    private boolean isCallerSensitive(final String owner, final String name, final String descriptor) {
        return isCallerSensitive(owner, name, descriptor, new java.util.HashSet<>());
    }

    private boolean isCallerSensitive(
            final String owner,
            final String name,
            final String descriptor,
            final Set<String> visited
    ) {
        if (owner == null || !visited.add(owner)) return false;
        final org.mapleir.asm.ClassNode node = skidfuscator.getClassSource().findClassNode(owner);
        if (node == null || node.node == null) return false;
        for (final org.objectweb.asm.tree.MethodNode method : node.node.methods) {
            if (!method.name.equals(name) || !method.desc.equals(descriptor)) continue;
            final java.util.stream.Stream<org.objectweb.asm.tree.AnnotationNode> annotations =
                    java.util.stream.Stream.concat(
                            method.visibleAnnotations == null ? java.util.stream.Stream.empty()
                                    : method.visibleAnnotations.stream(),
                            method.invisibleAnnotations == null ? java.util.stream.Stream.empty()
                                    : method.invisibleAnnotations.stream());
            if (annotations.anyMatch(annotation ->
                    "Ljdk/internal/reflect/CallerSensitive;".equals(annotation.desc)
                            || "Lsun/reflect/CallerSensitive;".equals(annotation.desc))) {
                return true;
            }
        }
        if (node.node.interfaces != null) {
            for (final String interfaceName : node.node.interfaces) {
                if (isCallerSensitive(interfaceName, name, descriptor, visited)) return true;
            }
        }
        return isCallerSensitive(node.node.superName, name, descriptor, visited);
    }

    static ToolchainManifestUriResolver releaseManifestUris() {
        return version -> {
            if (version == null || !version.matches("[A-Za-z0-9][A-Za-z0-9._-]{0,127}")) {
                throw new IllegalArgumentException("Unsafe SkidLLVM release version: " + version);
            }
            return URI.create(DEFAULT_RELEASE_BASE + "v" + version + "/"
                    + dev.skidfuscator.nativetoolchain.ExternalToolchainLocator.MANIFEST_FILE_NAME);
        };
    }

    private static Set<dev.skidfuscator.nativetoolchain.NativeTarget> toolchainTargets(
            final Collection<NativeTarget> targets
    ) {
        return targets.stream().map(value ->
                dev.skidfuscator.nativetoolchain.NativeTarget.parse(value.getId()))
                .collect(Collectors.toCollection(LinkedHashSet::new));
    }

    private static VmProtectionSettings vmSettings(final NativeConfig config) {
        final var vm = config.getVmConfig();
        final VmProtectionSettings.Profile profile = VmProtectionSettings.Profile.valueOf(vm.getProfile().name());
        final VmProtectionSettings.Response response = VmProtectionSettings.Response.valueOf(vm.getResponse().name());
        final boolean aggressive = profile == VmProtectionSettings.Profile.AGGRESSIVE;
        return new VmProtectionSettings(profile, response, vm.isIntegrityEnabled(), vm.isAntiDebugEnabled(),
                vm.isAntiInstrumentationEnabled(), vm.isTimingChecksEnabled(), true,
                aggressive ? 4 : 2, aggressive ? 48 : 16, aggressive ? 64 : 32,
                response == VmProtectionSettings.Response.DELAYED_HALT ? 250 : 0);
    }

    /** Publishes optional target-specific jars after the universal output jar exists. */
    public void publishPlatformArtifacts() {
        if (!nativeArtifactsInstalled) {
            return;
        }
        final NativeConfig config = skidfuscator.getConfig().getNativeConfig();
        final NativeArtifactMode mode = config.getArtifactMode();
        if (mode == NativeArtifactMode.UNIVERSAL) {
            return;
        }
        final Path universalJar = skidfuscator.getSession().getOutput().toPath().toAbsolutePath().normalize();
        final File configuredDirectory = skidfuscator.getSession().getNativeArtifactDirectory();
        final String outputName = universalJar.getFileName().toString();
        final String baseName = outputName.toLowerCase(Locale.ROOT).endsWith(".jar")
                ? outputName.substring(0, outputName.length() - 4) : outputName;
        final Path parent = universalJar.getParent() == null
                ? Path.of(".").toAbsolutePath().normalize() : universalJar.getParent();
        final Path artifactDirectory = configuredDirectory == null
                ? parent.resolve(baseName + "-native")
                : configuredDirectory.toPath().toAbsolutePath().normalize();
        try {
            final Set<NativeTarget> targets = effectiveTargets(config, skidfuscator.getSession());
            final var outputs = NativeArtifactPackager.packagePlatformJars(
                    universalJar, artifactDirectory, targets);
            Skidfuscator.LOGGER.post("Published " + outputs.size()
                    + " platform-specific native jar(s) to " + artifactDirectory);
        } catch (IOException exception) {
            throw new NativeBackendUnavailableException(
                    "The universal native jar was written, but platform artifact publication failed: "
                            + exception.getMessage(), exception);
        }
    }

    private static void rejectLowering(
            final NativeCompilationPlan.Candidate candidate,
            final String reason,
            final List<NativeCompilationPlan.Skipped> skipped
    ) {
        if (candidate.selection().isStrict()) {
            throw new NativeSelectionException("Explicit native selection cannot be lowered: "
                    + candidate.selection().getMethod() + ": " + reason);
        }
        skipped.add(new NativeCompilationPlan.Skipped(candidate.selection(), reason));
    }

    private static Path explicitCompiler(final NativeConfig config, final SkidfuscatorSession session) {
        final File sessionPath = session.getNativeToolchainPath();
        if (sessionPath != null) {
            return sessionPath.toPath().toAbsolutePath().normalize();
        }
        final String configured = config.getToolchainConfig().getPath();
        return configured == null || configured.isBlank()
                ? null
                : Path.of(configured).toAbsolutePath().normalize();
    }

    private static String randomId() {
        final byte[] bytes = new byte[12];
        new SecureRandom().nextBytes(bytes);
        return HexFormat.of().formatHex(bytes);
    }

    private static void cleanupTemporaryDirectory(final Path directory) {
        final Path normalized = directory.toAbsolutePath().normalize();
        if (!normalized.getFileName().toString().startsWith("skid-native-")) {
            Skidfuscator.LOGGER.warn("Refusing to clean unexpected native work directory: " + normalized);
            return;
        }
        try (var paths = Files.walk(normalized)) {
            for (final Path path : paths.sorted(Comparator.reverseOrder()).toList()) {
                Files.deleteIfExists(path);
            }
        } catch (IOException exception) {
            Skidfuscator.LOGGER.warn("Unable to clean native work directory " + normalized
                    + ": " + exception.getMessage());
        }
    }

    private Request validateRequest(final NativeConfig config) {
        final SkidfuscatorSession session = skidfuscator.getSession();
        final var toolchain = config.getToolchainConfig();
        final String developmentPath = toolchain.getDevelopmentPath();
        if (toolchain.isDevelopmentEnabled()) {
            if (developmentPath.isBlank() || !Path.of(developmentPath).isAbsolute()) {
                throw new NativeSelectionException("Local native development requires an absolute "
                        + "native.toolchain.development.path to skidllvm");
            }
            if (explicitCompiler(config, session) != null) {
                throw new NativeSelectionException("Do not combine development.path with a release toolchain path");
            }
        } else if (!developmentPath.isBlank()) {
            throw new NativeSelectionException("development.path requires explicit "
                    + "native.toolchain.development.enabled=true; no unsigned fallback is automatic");
        }
        if (session.isDex()) {
            throw new NativeSelectionException("Native AOT/VM mode is not supported for APK/DEX output");
        }
        final Set<NativeTarget> targets = effectiveTargets(config, session);
        final NativeToolchainDelivery delivery = effectiveDelivery(config, session);
        if (delivery == NativeToolchainDelivery.DISABLED) {
            throw new NativeBackendUnavailableException(
                    "native.enabled is true but native.toolchain.delivery is DISABLED"
            );
        }
        return new Request(targets, delivery);
    }

    private Collection<SkidMethodNode> applicationMethods() {
        return skidfuscator.getHierarchy().getMethods().stream()
                .filter(method -> skidfuscator.getClassSource().isApplicationClass(method.owner.getName()))
                .collect(Collectors.toList());
    }

    private Collection<org.mapleir.asm.MethodNode> outputMethods() {
        if (skidfuscator.getJarContents() == null) return new ArrayList<>(applicationMethods());
        // Hierarchy.getMethods() omits exempt classes. Their bytecode and reflection
        // literals still require declarations in the output, so scan the whole jar.
        return skidfuscator.getJarContents().getClassContents().stream()
                .flatMap(data -> data.getClassNode().getMethods().stream()).toList();
    }

    static Set<NativeTarget> effectiveTargets(
            final NativeConfig config,
            final SkidfuscatorSession session
    ) {
        final String[] override = session.getNativeTargets();
        if (override == null || override.length == 0) {
            return new LinkedHashSet<>(config.getTargets());
        }
        final LinkedHashSet<NativeTarget> targets = Arrays.stream(override)
                .map(String::trim)
                .filter(value -> !value.isEmpty())
                .map(NativeTarget::fromConfigValue)
                .collect(Collectors.toCollection(LinkedHashSet::new));
        if (targets.isEmpty()) {
            throw new IllegalArgumentException("At least one native target is required");
        }
        return targets;
    }

    static NativeToolchainDelivery effectiveDelivery(
            final NativeConfig config,
            final SkidfuscatorSession session
    ) {
        final String override = session.getNativeToolchainDelivery();
        if (override == null || override.isBlank()) {
            return config.getToolchainConfig().getDelivery();
        }
        try {
            return NativeToolchainDelivery.valueOf(override.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException exception) {
            throw new IllegalArgumentException("Unsupported native toolchain delivery: " + override, exception);
        }
    }

    private record Request(Set<NativeTarget> targets, NativeToolchainDelivery delivery) {
    }

    private record Lowered(
            NativeCompilationPlan.Candidate candidate,
            NativeFunction function,
            NativeMethodCommitTransaction.Mutation mutation
    ) {
    }
}
