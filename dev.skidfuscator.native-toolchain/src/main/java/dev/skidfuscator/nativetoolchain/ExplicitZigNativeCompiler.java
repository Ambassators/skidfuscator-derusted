package dev.skidfuscator.nativetoolchain;

import dev.skidfuscator.nativeir.JavaDescriptor;
import dev.skidfuscator.nativeir.NativeBackend;
import dev.skidfuscator.nativeir.NativeBlock;
import dev.skidfuscator.nativeir.NativeFunction;
import dev.skidfuscator.nativeir.NativeInstruction;
import dev.skidfuscator.nativeir.NativeIrVerifier;
import dev.skidfuscator.nativeir.NativeModule;
import dev.skidfuscator.nativeir.NativeOpcode;
import dev.skidfuscator.nativeir.NativeType;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Pattern;

/**
 * Explicit development compiler used to prove the end-to-end JNI pipeline with
 * an absolute, user-supplied Zig executable.
 *
 * <p>This deliberately does not discover Zig from {@code PATH}, download it, or
 * pretend to be the signed SkidLLVM release. It is a small operational bridge
 * for the supported AOT subset while the separately signed SkidLLVM driver is
 * being built. Only zero-argument static methods returning a Java String are
 * accepted for now.</p>
 */
public final class ExplicitZigNativeCompiler {
    private static final Pattern BUILD_ID = Pattern.compile("[A-Za-z0-9._-]{1,128}");
    private static final Pattern C_SYMBOL = Pattern.compile("[A-Za-z_][A-Za-z0-9_]*");
    private static final Duration DEFAULT_TIMEOUT = Duration.ofMinutes(10);

    private final LlvmIrEmitter emitter;
    private final NativeIrVerifier verifier;
    private final NativeLibraryValidator libraryValidator;
    private final ProcessExecutor executor;
    private final Duration timeout;

    public ExplicitZigNativeCompiler(final LlvmIrEmitter emitter) {
        this(emitter, new NativeIrVerifier(), new NativeLibraryValidator(),
                new SystemProcessExecutor(), DEFAULT_TIMEOUT);
    }

    ExplicitZigNativeCompiler(
            final LlvmIrEmitter emitter,
            final NativeIrVerifier verifier,
            final NativeLibraryValidator libraryValidator,
            final ProcessExecutor executor,
            final Duration timeout
    ) {
        this.emitter = Objects.requireNonNull(emitter, "emitter");
        this.verifier = Objects.requireNonNull(verifier, "verifier");
        this.libraryValidator = Objects.requireNonNull(libraryValidator, "libraryValidator");
        this.executor = Objects.requireNonNull(executor, "executor");
        this.timeout = Objects.requireNonNull(timeout, "timeout");
    }

    public NativeCompilationResult compile(
            final NativeModule module,
            final Path zigExecutable,
            final Path outputDirectory,
            final Collection<NativeTarget> requestedTargets,
            final String buildId
    ) throws IOException, InterruptedException {
        Objects.requireNonNull(module, "module");
        Objects.requireNonNull(zigExecutable, "zigExecutable");
        Objects.requireNonNull(outputDirectory, "outputDirectory");
        Objects.requireNonNull(requestedTargets, "requestedTargets");
        if (!BUILD_ID.matcher(Objects.requireNonNull(buildId, "buildId")).matches()) {
            throw new IllegalArgumentException("Invalid native build id: " + buildId);
        }
        final Path compiler = zigExecutable.toAbsolutePath().normalize();
        if (!Files.isRegularFile(compiler)) {
            throw new IOException("Explicit Zig compiler is missing: " + compiler);
        }
        final Set<NativeTarget> targets = Set.copyOf(requestedTargets);
        if (targets.isEmpty()) {
            throw new IllegalArgumentException("At least one native target is required");
        }
        verifier.verifyOrThrow(module);
        validateSupportedFunctions(module);

        final Path output = outputDirectory.toAbsolutePath().normalize();
        Files.createDirectories(output);
        final Path llvmPath = output.resolve(buildId + ".ll");
        writeAtomically(llvmPath, emitter.emit(module));
        final Path runtimePath = output.resolve(buildId + "-jni.c");
        writeAtomically(runtimePath, runtimeSource(module).getBytes(StandardCharsets.UTF_8));

        final Path javaHome = findJdkHome();
        final Map<NativeTarget, Path> libraries = new EnumMap<>(NativeTarget.class);
        final Map<NativeTarget, NativeArtifact> artifacts = new EnumMap<>(NativeTarget.class);
        for (final NativeTarget target : NativeTarget.values()) {
            if (!targets.contains(target)) continue;
            if (target != NativeTarget.WINDOWS_X86_64) {
                throw new NativeCompilationException(
                        "The explicit Zig development compiler currently supports windows-x86_64 only; "
                                + "use signed SkidLLVM for " + target.id());
            }

            final Path targetDirectory = output.resolve(target.id());
            Files.createDirectories(targetDirectory);
            final String libraryName = target.libraryFileName("skid-" + buildId);
            final Path finalLibrary = targetDirectory.resolve(libraryName);
            final Path partialLibrary = targetDirectory.resolve(libraryName + ".partial");
            Files.deleteIfExists(partialLibrary);

            final List<String> command = new ArrayList<>();
            command.add(compiler.toString());
            command.add("cc");
            command.add("-target");
            command.add("x86_64-windows-gnu");
            command.add("-shared");
            command.add("-O2");
            command.add("-fvisibility=hidden");
            command.add("-I");
            command.add(javaHome.resolve("include").toString());
            command.add("-I");
            command.add(javaHome.resolve("include").resolve("win32").toString());
            command.add(llvmPath.toString());
            command.add(runtimePath.toString());
            command.add("-o");
            command.add(partialLibrary.toString());

            final ProcessExecutor.Result result = executor.execute(command, output, timeout);
            if (result.timedOut()) {
                Files.deleteIfExists(partialLibrary);
                throw new NativeCompilationException("Explicit Zig compiler timed out for " + target.id());
            }
            if (result.exitCode() != 0) {
                Files.deleteIfExists(partialLibrary);
                throw new NativeCompilationException("Explicit Zig compiler failed for " + target.id()
                        + " (exit " + result.exitCode() + "): " + bounded(result.output()));
            }
            libraryValidator.validate(partialLibrary, target);
            moveAtomically(partialLibrary, finalLibrary);
            libraries.put(target, finalLibrary);

            final String resourcePath = "META-INF/skidfuscator/native/" + buildId + "/"
                    + target.id() + "/" + libraryName;
            artifacts.put(target, new NativeArtifact(
                    target, resourcePath, sha256(finalLibrary), Files.size(finalLibrary)));
        }

        final CompilerManifest manifest = new CompilerManifest(
                CompilerManifest.CURRENT_SCHEMA,
                module.abiVersion(),
                buildId,
                sha256(llvmPath),
                artifacts
        );
        new CompilerManifestValidator().validateOrThrow(manifest);
        return new NativeCompilationResult(manifest, llvmPath, libraries);
    }

    private static void validateSupportedFunctions(final NativeModule module)
            throws NativeCompilationException {
        if (module.functions().isEmpty()) {
            throw new NativeCompilationException("Native module contains no functions");
        }
        for (final NativeFunction function : module.functions()) {
            final JavaDescriptor.Method descriptor;
            try {
                descriptor = JavaDescriptor.method(function.javaDescriptor());
            } catch (IllegalArgumentException exception) {
                throw new NativeCompilationException("Invalid descriptor for " + function.symbol()
                        + ": " + exception.getMessage());
            }
            if (function.backend() != NativeBackend.AOT
                    || !descriptor.parameters().isEmpty()
                    || !(descriptor.returnType() instanceof NativeType.Reference reference)
                    || !"java/lang/String".equals(reference.internalName())
                    || !"true".equals(function.metadata().get("java.static"))
                    || !function.requiresSemanticContext()
                    || !"jni".equals(function.metadata().get("semanticContext"))
                    || !C_SYMBOL.matcher(function.symbol()).matches()) {
                throw new NativeCompilationException(
                        "Explicit Zig compiler only accepts semantic-context AOT functions for "
                                + "zero-argument static methods returning java.lang.String: "
                                + function.javaOwner() + "#" + function.javaName()
                                + function.javaDescriptor());
            }
            // This developer bridge has a string runtime, not the production semantic
            // dispatcher. Reject unsupported bodies before launching a compiler.
            if (function.blocks().size() != 1) {
                throw new NativeCompilationException("Explicit Zig compiler requires a single literal-return block");
            }
            final NativeBlock block = function.blocks().get(0);
            if (!block.exceptionEdges().isEmpty() || block.instructions().size() != 1
                    || !(block.instructions().get(0) instanceof NativeInstruction.Operation literal)
                    || literal.opcode() != NativeOpcode.STRING_CONSTANT
                    || !(block.terminator().orElse(null) instanceof dev.skidfuscator.nativeir.NativeTerminator.Return returning)
                    || !(returning.value().orElse(null) instanceof dev.skidfuscator.nativeir.NativeOperand.Value value)
                    || !value.id().equals(literal.id())) {
                throw new NativeCompilationException(
                        "Explicit Zig compiler supports only a literal String return without exception handlers");
            }
            requireAscii(block.id(), "Native block id");
            requireAscii(function.javaOwner(), "Java owner");
            requireAscii(function.javaName(), "Java method name");
            requireAscii(function.javaDescriptor(), "Java method descriptor");
        }
    }

    private static String runtimeSource(final NativeModule module)
            throws NativeCompilationException {
        final List<NativeFunction> functions = module.functions().stream()
                .sorted(Comparator.comparing(NativeFunction::javaOwner)
                        .thenComparing(NativeFunction::javaName)
                        .thenComparing(NativeFunction::javaDescriptor))
                .toList();
        final int protectedStringCount = protectedStringCount(module);
        final StringBuilder c = new StringBuilder(12_288);
        appendStringRuntime(c, protectedStringCount);

        for (int index = 0; index < functions.size(); index++) {
            final NativeFunction function = functions.get(index);
            final String exceptionSite = "skid.semantic.site.v1." + function.symbol() + "."
                    + function.blocks().get(0).id() + ".exception-dispatch";
            c.append("int32_t skid_exception_site_").append(index)
                    .append("(void *context) __asm__(\"").append(cString(exceptionSite)).append("\");\n")
                    .append("int32_t skid_exception_site_").append(index).append("(void *context) {\n")
                    .append("    JNIEnv *env = (JNIEnv *) context;\n")
                    .append("    return env != 0 && !(*env)->ExceptionCheck(env) ? -1 : -2;\n")
                    .append("}\n\n");
            c.append("extern void *").append(function.symbol()).append("(void *semantic_context);\n")
                    .append("static jstring JNICALL skid_trampoline_").append(index)
                    .append("(JNIEnv *env, jclass owner) {\n")
                    .append("    (void) owner;\n")
                    .append("    return (jstring) ").append(function.symbol()).append("((void *) env);\n")
                    .append("}\n\n");
        }

        final Map<String, List<Integer>> byOwner = new LinkedHashMap<>();
        for (int index = 0; index < functions.size(); index++) {
            byOwner.computeIfAbsent(functions.get(index).javaOwner(), ignored -> new ArrayList<>()).add(index);
        }
        int ownerIndex = 0;
        for (final Map.Entry<String, List<Integer>> entry : byOwner.entrySet()) {
            c.append("static JNINativeMethod skid_methods_").append(ownerIndex).append("[] = {\n");
            for (final int functionIndex : entry.getValue()) {
                final NativeFunction function = functions.get(functionIndex);
                c.append("    { \"").append(cString(function.javaName())).append("\", \"")
                        .append(cString(function.javaDescriptor())).append("\", (void *) skid_trampoline_")
                        .append(functionIndex).append(" },\n");
            }
            c.append("};\n\n");
            ownerIndex++;
        }

        c.append("JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {\n")
                .append("    JNIEnv *env = 0;\n    (void) reserved;\n")
                .append("    if ((*vm)->GetEnv(vm, (void **) &env, JNI_VERSION_1_8) != JNI_OK) return JNI_ERR;\n")
                .append("    {\n")
                .append("        jclass string_class = (*env)->FindClass(env, \"java/lang/String\");\n")
                .append("        if (string_class == 0 || (*env)->ExceptionCheck(env)) return JNI_ERR;\n")
                .append("        skid_string_intern = (*env)->GetMethodID(env, string_class, \"intern\", ")
                .append("\"()Ljava/lang/String;\");\n")
                .append("        if (skid_string_intern == 0 || (*env)->ExceptionCheck(env)) return JNI_ERR;\n")
                .append("        (*env)->DeleteLocalRef(env, string_class);\n")
                .append("    }\n");
        ownerIndex = 0;
        for (final Map.Entry<String, List<Integer>> entry : byOwner.entrySet()) {
            c.append("    {\n        jclass owner = (*env)->FindClass(env, \"")
                    .append(cString(entry.getKey())).append("\");\n")
                    .append("        if (owner == 0) return JNI_ERR;\n")
                    .append("        if ((*env)->RegisterNatives(env, owner, skid_methods_")
                    .append(ownerIndex).append(", (jint) (sizeof(skid_methods_").append(ownerIndex)
                    .append(") / sizeof(skid_methods_").append(ownerIndex)
                    .append("[0]))) != JNI_OK) return JNI_ERR;\n")
                    .append("        (*env)->DeleteLocalRef(env, owner);\n    }\n");
            ownerIndex++;
        }
        c.append("    return JNI_VERSION_1_8;\n}\n");
        return c.toString();
    }

    private static int protectedStringCount(final NativeModule module) {
        final Set<String> values = new TreeSet<>();
        for (final NativeFunction function : module.functions()) {
            for (final NativeBlock block : function.blocks()) {
                for (final NativeInstruction instruction : block.instructions()) {
                    if (instruction instanceof NativeInstruction.Operation operation
                            && operation.opcode() == NativeOpcode.STRING_CONSTANT) {
                        final String value = operation.attributes().get("value");
                        if (value != null) values.add(value);
                    }
                }
            }
        }
        return values.size();
    }

    /**
     * Emits the JNI semantic helper shared by the deterministic and protected
     * LLVM emitters. The protected ABI is versioned independently so a legacy
     * canonical module cannot accidentally reinterpret ciphertext as plaintext.
     */
    private static void appendStringRuntime(final StringBuilder c, final int protectedStringCount) {
        final int cacheCapacity = Math.max(1, protectedStringCount);
        c.append("#include <jni.h>\n")
                .append("#include <limits.h>\n")
                .append("#include <stddef.h>\n")
                .append("#include <stdint.h>\n")
                .append("#include <stdatomic.h>\n")
                .append("#include <stdlib.h>\n\n")
                .append("#define SKID_MAX_STRING_UNITS 1048576\n")
                .append("#define SKID_STRING_CACHE_COUNT ").append(protectedStringCount).append("\n")
                .append("#define SKID_STRING_CACHE_CAPACITY ").append(cacheCapacity).append("\n\n")
                .append("typedef struct {\n")
                .append("    atomic_uintptr_t value;\n")
                .append("} skid_string_cache_entry;\n\n")
                .append("static skid_string_cache_entry skid_string_cache[SKID_STRING_CACHE_CAPACITY];\n")
                .append("static jmethodID skid_string_intern = 0;\n\n")
                .append("static void skid_secure_zero(void *value, size_t length) {\n")
                .append("    volatile uint8_t *cursor = (volatile uint8_t *) value;\n")
                .append("    while (length-- != 0) *cursor++ = 0;\n")
                .append("}\n\n")
                .append("static uint64_t skid_rotate_left_64(uint64_t value, unsigned int distance) {\n")
                .append("    return (value << distance) | (value >> (64U - distance));\n")
                .append("}\n\n")
                .append("static void skid_throw(JNIEnv *env, const char *type, const char *message) {\n")
                .append("    jclass exception_class;\n")
                .append("    if (env == 0 || (*env)->ExceptionCheck(env)) return;\n")
                .append("    exception_class = (*env)->FindClass(env, type);\n")
                .append("    if (exception_class == 0 || (*env)->ExceptionCheck(env)) return;\n")
                .append("    (void) (*env)->ThrowNew(env, exception_class, message);\n")
                .append("}\n\n")
                .append("static jstring skid_intern(JNIEnv *env, jstring created) {\n")
                .append("    jstring interned;\n")
                .append("    if (created == 0 || (*env)->ExceptionCheck(env)) return 0;\n")
                .append("    if (skid_string_intern == 0) {\n")
                .append("        skid_throw(env, \"java/lang/UnsatisfiedLinkError\", ")
                .append("\"native string runtime was not initialized\");\n")
                .append("        return 0;\n")
                .append("    }\n")
                .append("    interned = (jstring) (*env)->CallObjectMethod(env, created, skid_string_intern);\n")
                .append("    if (interned == 0 || (*env)->ExceptionCheck(env)) return 0;\n")
                .append("    return interned;\n")
                .append("}\n\n")
                .append("void *skid_string_constant(void *context, const uint16_t *value, int32_t length) ")
                .append("__asm__(\"skid.semantic.string_constant.v1\");\n")
                .append("void *skid_string_constant(void *context, const uint16_t *value, int32_t length) {\n")
                .append("    JNIEnv *env = (JNIEnv *) context;\n")
                .append("    jstring created;\n")
                .append("    if (env == 0) return 0;\n")
                .append("    if ((*env)->ExceptionCheck(env)) return 0;\n")
                .append("    if (value == 0 || length < 0 || length > SKID_MAX_STRING_UNITS) {\n")
                .append("        skid_throw(env, \"java/lang/IllegalArgumentException\", ")
                .append("\"invalid native string constant\");\n")
                .append("        return 0;\n")
                .append("    }\n")
                .append("    created = (*env)->NewString(env, (const jchar *) value, (jsize) length);\n")
                .append("    if (created == 0 || (*env)->ExceptionCheck(env)) return 0;\n")
                .append("    return (void *) skid_intern(env, created);\n")
                .append("}\n\n")
                .append("void *skid_protected_string_constant(void *context, const uint16_t *ciphertext, ")
                .append("int32_t length, int32_t cache_index, uint64_t fragment_a, uint64_t fragment_b) ")
                .append("__asm__(\"skid.semantic.string_constant.protected.v1\");\n")
                .append("void *skid_protected_string_constant(void *context, const uint16_t *ciphertext, ")
                .append("int32_t length, int32_t cache_index, uint64_t fragment_a, uint64_t fragment_b) {\n")
                .append("    JNIEnv *env = (JNIEnv *) context;\n")
                .append("    skid_string_cache_entry *entry;\n")
                .append("    jchar *plaintext;\n")
                .append("    size_t byte_count;\n")
                .append("    uint64_t key_material[4];\n")
                .append("    jstring created;\n")
                .append("    jstring interned;\n")
                .append("    jobject global;\n")
                .append("    uintptr_t expected_value;\n")
                .append("    if (env == 0) return 0;\n")
                .append("    if ((*env)->ExceptionCheck(env)) return 0;\n")
                .append("    if (ciphertext == 0 || length < 0 || length > SKID_MAX_STRING_UNITS\n")
                .append("            || cache_index < 0 || cache_index >= SKID_STRING_CACHE_COUNT\n")
                .append("            || (size_t) length > SIZE_MAX / sizeof(jchar)) {\n")
                .append("        skid_throw(env, \"java/lang/IllegalArgumentException\", ")
                .append("\"invalid protected native string constant\");\n")
                .append("        return 0;\n")
                .append("    }\n")
                .append("    entry = &skid_string_cache[cache_index];\n")
                .append("    expected_value = atomic_load_explicit(&entry->value, memory_order_acquire);\n")
                .append("    if (expected_value != 0)\n")
                .append("        return (void *) (*env)->NewLocalRef(env, (jobject) expected_value);\n")
                .append("    byte_count = (size_t) length * sizeof(jchar);\n")
                .append("    plaintext = (jchar *) malloc(byte_count == 0 ? sizeof(jchar) : byte_count);\n")
                .append("    if (plaintext == 0) {\n")
                .append("        skid_throw(env, \"java/lang/OutOfMemoryError\", ")
                .append("\"unable to allocate protected native string\");\n")
                .append("        return 0;\n")
                .append("    }\n")
                .append("    key_material[0] = fragment_a;\n")
                .append("    key_material[1] = fragment_b;\n")
                .append("    key_material[2] = key_material[0] ^ skid_rotate_left_64(key_material[1], 17U)\n")
                .append("            ^ UINT64_C(0xD6E8FEB86659FD93);\n")
                .append("    key_material[3] = key_material[2];\n")
                .append("    for (int32_t index = 0; index < length; index++) {\n")
                .append("        uint64_t mixed;\n")
                .append("        key_material[3] += UINT64_C(0x9E3779B97F4A7C15);\n")
                .append("        mixed = key_material[3];\n")
                .append("        mixed = (mixed ^ (mixed >> 30)) * UINT64_C(0xBF58476D1CE4E5B9);\n")
                .append("        mixed = (mixed ^ (mixed >> 27)) * UINT64_C(0x94D049BB133111EB);\n")
                .append("        mixed ^= mixed >> 31;\n")
                .append("        plaintext[index] = (jchar) (ciphertext[index] ^ (uint16_t) mixed);\n")
                .append("        mixed = 0;\n")
                .append("    }\n")
                .append("    created = (*env)->NewString(env, plaintext, (jsize) length);\n")
                .append("    skid_secure_zero(plaintext, byte_count == 0 ? sizeof(jchar) : byte_count);\n")
                .append("    skid_secure_zero(key_material, sizeof(key_material));\n")
                .append("    free(plaintext);\n")
                .append("    if (created == 0 || (*env)->ExceptionCheck(env)) {\n")
                .append("        return 0;\n")
                .append("    }\n")
                .append("    interned = skid_intern(env, created);\n")
                .append("    if (interned == 0 || (*env)->ExceptionCheck(env)) {\n")
                .append("        return 0;\n")
                .append("    }\n")
                .append("    global = (*env)->NewGlobalRef(env, interned);\n")
                .append("    if (global == 0 || (*env)->ExceptionCheck(env)) {\n")
                .append("        if (global == 0 && !(*env)->ExceptionCheck(env))\n")
                .append("            skid_throw(env, \"java/lang/OutOfMemoryError\", ")
                .append("\"unable to cache protected native string\");\n")
                .append("        return 0;\n")
                .append("    }\n")
                .append("    expected_value = 0;\n")
                .append("    if (!atomic_compare_exchange_strong_explicit(&entry->value, &expected_value,\n")
                .append("            (uintptr_t) global, memory_order_acq_rel, memory_order_acquire)) {\n")
                .append("        (*env)->DeleteGlobalRef(env, global);\n")
                .append("        if (expected_value == 0) {\n")
                .append("            skid_throw(env, \"java/lang/InternalError\", ")
                .append("\"native string cache publication failed\");\n")
                .append("            return 0;\n")
                .append("        }\n")
                .append("        return (void *) (*env)->NewLocalRef(env, (jobject) expected_value);\n")
                .append("    }\n")
                .append("    return (void *) interned;\n")
                .append("}\n\n")
                .append("/* The bounded cache holds only interned bootstrap String objects. It therefore\n")
                .append(" * cannot retain an application class loader. JNI_OnUnload is intentionally not\n")
                .append(" * exported so JNI_OnLoad remains the DLL's sole public symbol. */\n\n");
    }

    private static Path findJdkHome() throws IOException {
        Path home = Path.of(System.getProperty("java.home")).toAbsolutePath().normalize();
        if (!Files.isRegularFile(home.resolve("include").resolve("jni.h")) && home.getParent() != null) {
            home = home.getParent();
        }
        if (!Files.isRegularFile(home.resolve("include").resolve("jni.h"))
                || !Files.isDirectory(home.resolve("include").resolve("win32"))) {
            throw new IOException("A full Windows JDK with JNI headers is required; java.home="
                    + System.getProperty("java.home"));
        }
        return home;
    }

    private static void requireAscii(final String value, final String label)
            throws NativeCompilationException {
        for (int index = 0; index < value.length(); index++) {
            final char current = value.charAt(index);
            if (current < 0x20 || current > 0x7e || current == '"' || current == '\\') {
                throw new NativeCompilationException(label + " is not supported by the initial JNI table: " + value);
            }
        }
    }

    private static String cString(final String value) throws NativeCompilationException {
        requireAscii(value, "JNI registration value");
        return value;
    }

    private static void writeAtomically(final Path target, final byte[] contents) throws IOException {
        final Path partial = target.resolveSibling(target.getFileName() + ".partial");
        Files.write(partial, contents);
        moveAtomically(partial, target);
    }

    private static void moveAtomically(final Path source, final Path target) throws IOException {
        try {
            Files.move(source, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } catch (AtomicMoveNotSupportedException ignored) {
            Files.move(source, target, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private static String sha256(final Path path) throws IOException {
        try {
            final MessageDigest digest = MessageDigest.getInstance("SHA-256");
            try (var input = Files.newInputStream(path)) {
                final byte[] buffer = new byte[8192];
                int read;
                while ((read = input.read(buffer)) != -1) digest.update(buffer, 0, read);
            }
            return HexFormat.of().formatHex(digest.digest());
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
    }

    private static String bounded(final String output) {
        final String normalized = output == null ? "" : output.trim();
        return normalized.length() <= 4096 ? normalized : normalized.substring(0, 4096) + " [truncated]";
    }
}
