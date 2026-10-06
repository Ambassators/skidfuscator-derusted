package dev.skidfuscator.nativetoolchain;

import dev.skidfuscator.nativeir.NativeIrVerifier;
import dev.skidfuscator.nativeir.NativeBackend;
import dev.skidfuscator.nativetoolchain.vm.VmBytecodeCompiler;
import dev.skidfuscator.nativetoolchain.vm.VmProgramCodec;

import java.io.IOException;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/** Emits canonical LLVM IR and invokes the pinned SkidLLVM driver once per target. */
public final class ProcessNativeCompiler implements NativeCompiler {
    public static final String DRIVER_BASE_NAME = "skidllvm";
    public static final Duration DEFAULT_TIMEOUT = Duration.ofMinutes(10);

    private final LlvmIrEmitter emitter;
    private final ProcessExecutor executor;
    private final Duration timeout;
    private final NativeIrVerifier verifier;
    private final NativeLibraryValidator libraryValidator;

    public ProcessNativeCompiler(final LlvmIrEmitter emitter) {
        this(emitter, new SystemProcessExecutor(), DEFAULT_TIMEOUT, new NativeIrVerifier(),
                new NativeLibraryValidator());
    }

    public ProcessNativeCompiler(
            final LlvmIrEmitter emitter,
            final ProcessExecutor executor,
            final Duration timeout,
            final NativeIrVerifier verifier
    ) {
        this(emitter, executor, timeout, verifier, new NativeLibraryValidator());
    }

    ProcessNativeCompiler(
            final LlvmIrEmitter emitter,
            final ProcessExecutor executor,
            final Duration timeout,
            final NativeIrVerifier verifier,
            final NativeLibraryValidator libraryValidator
    ) {
        this.emitter = Objects.requireNonNull(emitter, "emitter");
        this.executor = Objects.requireNonNull(executor, "executor");
        this.timeout = Objects.requireNonNull(timeout, "timeout");
        this.verifier = Objects.requireNonNull(verifier, "verifier");
        this.libraryValidator = Objects.requireNonNull(libraryValidator, "libraryValidator");
        if (timeout.isZero() || timeout.isNegative()) {
            throw new IllegalArgumentException("timeout must be positive");
        }
    }

    @Override
    public NativeCompilationResult compile(final NativeCompilationRequest request)
            throws IOException, InterruptedException {
        Objects.requireNonNull(request, "request");
        verifier.verifyOrThrow(request.module());
        ToolchainManifestVerifier.verifyInstalledDriver(
                request.toolchain().home(), request.toolchain().manifest(), request.currentHost());
        return compileModule(new CompilationInputs(request.module(), request.outputDirectory(),
                request.targets(), request.currentHost(), request.buildId(), request.vmProtection()),
                executable(request.toolchain().home(), request.currentHost()));
    }

    /**
     * Explicit, unsigned developer entrypoint. Never used as a resolver fallback.
     * Requires an absolute local SkidLLVM driver, the current host only, and AOT
     * functions only. Release compilation continues to require authentication.
     */
    public NativeCompilationResult compileExplicitLocalAot(
            final dev.skidfuscator.nativeir.NativeModule module,
            final Path driver,
            final Path outputDirectory,
            final java.util.Set<NativeTarget> targets,
            final NativeTarget currentHost,
            final String buildId,
            final String expectedVersion
    ) throws IOException, InterruptedException {
        Objects.requireNonNull(module, "module");
        Objects.requireNonNull(driver, "driver");
        Objects.requireNonNull(outputDirectory, "outputDirectory");
        Objects.requireNonNull(currentHost, "currentHost");
        final java.util.Set<NativeTarget> selected = java.util.Set.copyOf(targets);
        if (!driver.isAbsolute() || !Files.isRegularFile(driver)) {
            throw new NativeCompilationException("Local development requires an absolute existing SkidLLVM driver");
        }
        if (!selected.equals(java.util.Set.of(currentHost))) {
            throw new NativeCompilationException("Local development supports the current host target only");
        }
        if (module.functions().isEmpty() || module.functions().stream()
                .anyMatch(function -> function.backend() != NativeBackend.AOT)) {
            throw new NativeCompilationException("Local development is AOT-only; VM functions are not accepted");
        }
        if (buildId == null || !buildId.matches("[A-Za-z0-9._-]{1,128}")) {
            throw new IllegalArgumentException("Invalid native build id");
        }
        if (expectedVersion == null || !expectedVersion.matches("[A-Za-z0-9._-]{1,128}")) {
            throw new IllegalArgumentException("Invalid SkidLLVM development version");
        }
        verifier.verifyOrThrow(module);
        final Path output = outputDirectory.toAbsolutePath().normalize();
        Files.createDirectories(output);
        final Path executable = driver.toRealPath();
        final ProcessExecutor.Result version = executor.execute(
                List.of(executable.toString(), "--version"), output, Duration.ofSeconds(30));
        final String required = "SkidLLVM " + expectedVersion
                + " (LLVM 18.1.8, native IR ABI " + module.abiVersion() + ")";
        if (version.timedOut() || version.exitCode() != 0 || !required.equals(version.output().strip())) {
            throw new NativeCompilationException("Local SkidLLVM version/ABI check failed: " + bounded(version.output()));
        }
        return compileModule(new CompilationInputs(module, output, selected, currentHost,
                buildId, VmProtectionSettings.aggressive()), executable);
    }

    private record CompilationInputs(
            dev.skidfuscator.nativeir.NativeModule module, Path outputDirectory,
            java.util.Set<NativeTarget> targets, NativeTarget currentHost,
            String buildId, VmProtectionSettings vmProtection) { }

    private NativeCompilationResult compileModule(final CompilationInputs request, final Path driver)
            throws IOException, InterruptedException {
        verifier.verifyOrThrow(request.module());
        Files.createDirectories(request.outputDirectory());
        final boolean selectiveEntries = request.module().functions().stream()
                .anyMatch(function -> function.metadata().containsKey("java.entry"));
        final boolean reviewedEntries = request.module().functions().stream()
                .anyMatch(function -> "closed-world-v1".equals(function.metadata().get("java.entryScope")));
        final boolean crossClassEntries = request.module().functions().stream()
                .anyMatch(function -> "cross-class-v1".equals(function.metadata().get("java.entryCalls")));
        final boolean nativeFields = request.module().functions().stream().flatMap(f->f.blocks().stream())
                .flatMap(b->b.instructions().stream()).filter(dev.skidfuscator.nativeir.NativeInstruction.Operation.class::isInstance)
                .map(dev.skidfuscator.nativeir.NativeInstruction.Operation.class::cast)
                .anyMatch(op->op.attributes().containsKey("native.field.storage"));
        final boolean cppProtobuf = request.module().functions().stream()
                .anyMatch(f -> f.metadata().containsKey("cpp.protobuf.kernel") || f.metadata().containsKey("cpp.windows.scanner"));
        final boolean cppScanner = request.module().functions().stream().anyMatch(f->f.metadata().containsKey("cpp.windows.scanner"));
        if (cppProtobuf && !request.module().metadata().containsKey("cpp.protobuf.bundle"))
            throw new NativeCompilationException("C++ protobuf region has no compilation bundle");
        if ("class-local-v1".equals(request.module().metadata().get("registration")) || selectiveEntries || nativeFields || cppProtobuf) {
            final ProcessExecutor.Result contract = executor.execute(List.of(driver.toString(), "--contract"),
                    request.outputDirectory(), Duration.ofSeconds(30));
            if (contract.timedOut() || contract.exitCode() != 0
                    || !contract.output().contains("\"class-local-registration-v1\"")) {
                throw new NativeCompilationException("SkidLLVM lacks required class-local-registration-v1 capability");
            }
            if (selectiveEntries && !contract.output().contains("\"selective-java-entries-v1\"")) {
                throw new NativeCompilationException("SkidLLVM lacks required selective-java-entries-v1 capability");
            }
            if (reviewedEntries && !contract.output().contains("\"closed-world-java-entries-v1\"")) {
                throw new NativeCompilationException("SkidLLVM lacks required closed-world-java-entries-v1 capability");
            }
            if (crossClassEntries && !contract.output().contains("\"cross-class-java-entries-v1\"")) {
                throw new NativeCompilationException("SkidLLVM lacks required cross-class-java-entries-v1 capability");
            }
            if(nativeFields && !contract.output().contains("\"native-primitive-fields-v1\""))
                throw new NativeCompilationException("SkidLLVM lacks required native-primitive-fields-v1 capability");
            if(cppProtobuf && !contract.output().contains("\"cpp-protobuf-batch-v1\""))
                throw new NativeCompilationException("SkidLLVM lacks required cpp-protobuf-batch-v1 capability");
            if(cppScanner && !contract.output().contains("\"cpp-current-jvm-scanner-v1\""))
                throw new NativeCompilationException("SkidLLVM lacks required cpp-current-jvm-scanner-v1 capability");
        }

        final byte[] llvmIr = Objects.requireNonNull(emitter.emit(request.module()), "emitter result");
        if (llvmIr.length == 0) {
            throw new NativeCompilationException("LLVM emitter produced an empty module");
        }
        final Path llvmPath = request.outputDirectory().resolve(request.buildId() + ".ll");
        writeAtomically(llvmPath, llvmIr);
        final boolean hasVmFunctions = request.module().functions().stream()
                .anyMatch(function -> function.backend() == NativeBackend.VM);
        final Path vmPayload = hasVmFunctions
                ? request.outputDirectory().resolve(request.buildId() + ".skvm.partial") : null;
        if (vmPayload != null) {
            final VmProgramCodec vmCodec = new VmProgramCodec();
            final byte[] encodedVm = vmCodec.encode(new VmBytecodeCompiler().compile(
                    request.module(), request.buildId(), new SecureRandom(), request.vmProtection()));
            try {
                vmCodec.decode(encodedVm);
                Files.write(vmPayload, encodedVm);
            } finally {
                java.util.Arrays.fill(encodedVm, (byte) 0);
            }
        }
        try {
            final String moduleDigest = sha256(llvmPath);

            final Map<NativeTarget, Path> libraries = new EnumMap<>(NativeTarget.class);
            final Map<NativeTarget, NativeArtifact> artifacts = new EnumMap<>(NativeTarget.class);
            final List<Path> publishedLibraries = new ArrayList<>();
            boolean compilationComplete = false;
            try {
                for (final NativeTarget target : NativeTarget.values()) {
                    if (!request.targets().contains(target)) {
                        continue;
                    }
                    final Path targetDirectory = request.outputDirectory().resolve(target.id());
                    Files.createDirectories(targetDirectory);
                    final String libraryName = target.libraryFileName("skid-" + request.buildId());
                    final Path finalLibrary = targetDirectory.resolve(libraryName);
                    final Path temporaryLibrary = targetDirectory.resolve(libraryName + ".partial");
                    Files.deleteIfExists(temporaryLibrary);

                    final List<String> command = new ArrayList<>();
                    command.add(driver.toString());
                    command.add("compile");
                    command.add("--input");
                    command.add(llvmPath.toString());
                    command.add("--output");
                    command.add(temporaryLibrary.toString());
                    command.add("--target");
                    command.add(target.id());
                    command.add("--native-ir-abi");
                    command.add(Integer.toString(request.module().abiVersion()));
                    command.add("--build-id");
                    command.add(request.buildId());
                    if (cppProtobuf) {
                        command.add("--cpp-bundle");
                        command.add(request.module().metadata().get("cpp.protobuf.bundle"));
                    }
                    if (vmPayload != null) {
                        command.add("--vm-payload");
                        command.add(vmPayload.toString());
                        command.add("--vm-profile");
                        command.add(request.vmProtection().profile().name());
                        command.add("--vm-response");
                        command.add(request.vmProtection().response().name());
                        command.add("--vm-integrity=" + request.vmProtection().integrity());
                        command.add("--vm-anti-debug=" + request.vmProtection().antiDebug());
                        command.add("--vm-anti-instrumentation=" + request.vmProtection().antiInstrumentation());
                        command.add("--vm-timing-checks=" + request.vmProtection().timingChecks());
                        command.add("--vm-diversified-dispatch=" + request.vmProtection().diversifiedDispatch());
                        command.add("--vm-handler-clones=" + request.vmProtection().handlerCloneCount());
                        command.add("--vm-superinstructions=" + request.vmProtection().superinstructionBudget());
                        command.add("--vm-block-cache=" + request.vmProtection().decodedBlockCacheEntries());
                        command.add("--vm-delay-ms=" + request.vmProtection().delayedHaltMinimumMillis());
                    }

                    final ProcessExecutor.Result result = executor.execute(command, request.outputDirectory(), timeout);
                    Files.writeString(targetDirectory.resolve("compiler.log"),
                            result.output() == null ? "" : result.output(), java.nio.charset.StandardCharsets.UTF_8);
                    if (result.timedOut()) {
                        Files.deleteIfExists(temporaryLibrary);
                        throw new NativeCompilationException("SkidLLVM timed out compiling " + target.id());
                    }
                    if (result.exitCode() != 0) {
                        Files.deleteIfExists(temporaryLibrary);
                        throw new NativeCompilationException("SkidLLVM failed for " + target.id() + " (exit "
                                + result.exitCode() + "): " + bounded(result.output()));
                    }
                    if (!Files.isRegularFile(temporaryLibrary) || Files.size(temporaryLibrary) == 0) {
                        Files.deleteIfExists(temporaryLibrary);
                        throw new NativeCompilationException("SkidLLVM produced no library for " + target.id());
                    }
                    try {
                        libraryValidator.validate(temporaryLibrary, target);
                    } catch (IOException validationFailure) {
                        Files.deleteIfExists(temporaryLibrary);
                        throw validationFailure;
                    }
                    moveAtomically(temporaryLibrary, finalLibrary);
                    publishedLibraries.add(finalLibrary);
                    libraries.put(target, finalLibrary);
                    final String resourcePath = "META-INF/skidfuscator/native/" + request.buildId() + "/"
                            + target.id() + "/" + libraryName;
                    artifacts.put(target, new NativeArtifact(
                            target, resourcePath, sha256(finalLibrary), Files.size(finalLibrary)));
                }

                final CompilerManifest manifest = new CompilerManifest(
                        CompilerManifest.CURRENT_SCHEMA,
                        request.module().abiVersion(),
                        request.buildId(),
                        moduleDigest,
                        artifacts
                );
                new CompilerManifestValidator().validateOrThrow(manifest);
                compilationComplete = true;
                return new NativeCompilationResult(manifest, llvmPath, libraries);
            } finally {
                if (!compilationComplete) {
                    for (final Path publishedLibrary : publishedLibraries) {
                        Files.deleteIfExists(publishedLibrary);
                    }
                }
            }
        } finally {
            if (vmPayload != null) {
                clearAndDelete(vmPayload);
            }
        }
    }

    public static Path executable(final Path toolchainHome, final NativeTarget host) {
        final boolean windows = host == NativeTarget.WINDOWS_X86_64 || host == NativeTarget.WINDOWS_AARCH64;
        return toolchainHome.resolve("bin").resolve(DRIVER_BASE_NAME + (windows ? ".exe" : ""));
    }

    private static String sha256(final Path path) throws IOException {
        try {
            final MessageDigest digest = MessageDigest.getInstance("SHA-256");
            try (var input = Files.newInputStream(path)) {
                final byte[] buffer = new byte[8192];
                int read;
                while ((read = input.read(buffer)) >= 0) {
                    digest.update(buffer, 0, read);
                }
            }
            return HexFormat.of().formatHex(digest.digest());
        } catch (final NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
    }

    private static void writeAtomically(final Path target, final byte[] contents) throws IOException {
        final Path temporary = target.resolveSibling(target.getFileName() + ".partial");
        Files.write(temporary, contents);
        moveAtomically(temporary, target);
    }

    private static void clearAndDelete(final Path path) throws IOException {
        if (!Files.exists(path)) return;
        final long size = Files.size(path);
        try (var channel = java.nio.channels.FileChannel.open(path,
                java.nio.file.StandardOpenOption.WRITE)) {
            final java.nio.ByteBuffer zeros = java.nio.ByteBuffer.allocate(8192);
            long remaining = size;
            while (remaining > 0) {
                zeros.clear();
                zeros.limit((int) Math.min(zeros.capacity(), remaining));
                while (zeros.hasRemaining()) channel.write(zeros);
                remaining -= zeros.limit();
            }
            channel.force(true);
        } finally {
            Files.deleteIfExists(path);
        }
    }

    private static void moveAtomically(final Path source, final Path target) throws IOException {
        try {
            Files.move(source, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } catch (final AtomicMoveNotSupportedException ignored) {
            Files.move(source, target, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private static String bounded(final String output) {
        final String normalized = output == null ? "" : output.strip();
        return normalized.length() <= 4_096 ? normalized : normalized.substring(0, 4_096) + "…";
    }
}
