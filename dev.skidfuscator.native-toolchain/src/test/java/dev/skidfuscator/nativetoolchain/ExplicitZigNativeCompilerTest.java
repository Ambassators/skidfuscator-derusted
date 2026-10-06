package dev.skidfuscator.nativetoolchain;

import dev.skidfuscator.nativeir.NativeBackend;
import dev.skidfuscator.nativeir.NativeBlock;
import dev.skidfuscator.nativeir.NativeFunction;
import dev.skidfuscator.nativeir.NativeInstruction;
import dev.skidfuscator.nativeir.NativeModule;
import dev.skidfuscator.nativeir.NativeOpcode;
import dev.skidfuscator.nativeir.NativeOperand;
import dev.skidfuscator.nativeir.NativeTerminator;
import dev.skidfuscator.nativeir.NativeType;
import dev.skidfuscator.nativeir.SourceLocation;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class ExplicitZigNativeCompilerTest {
    private static final String SECRET_MARKER = "SKID_NATIVE_SECRET_92B0F7A4";
    private static final String EXPECTED = SECRET_MARKER + "\0\uD83D\uDE80\uDFFF";

    @TempDir
    Path temporary;

    @Test
    void compilesTheExplicitConstantStringAotSliceWhenZigIsProvided() throws Exception {
        final String configured = System.getenv("SKID_TEST_ZIG");
        assumeTrue(configured != null && Files.isRegularFile(Path.of(configured)),
                "SKID_TEST_ZIG must name an explicit Zig executable");
        assumeTrue(NativeTarget.currentHost().orElse(null) == NativeTarget.WINDOWS_X86_64,
                "Initial explicit compiler slice is Windows x86-64 only");

        final NativeType.Reference stringType = new NativeType.Reference("java/lang/String", false);
        final NativeInstruction.Operation literal = new NativeInstruction.Operation(
                "literal", stringType, NativeOpcode.STRING_CONSTANT, List.of(),
                Map.of("value", EXPECTED), SourceLocation.UNKNOWN);
        final NativeBlock entry = new NativeBlock("entry")
                .addInstruction(literal)
                .terminate(new NativeTerminator.Return(
                        java.util.Optional.of(new NativeOperand.Value(literal.id(), stringType)),
                        SourceLocation.UNKNOWN));
        final NativeFunction function = new NativeFunction(
                "skid_native_probe",
                ExplicitZigNativeCompilerTest.class.getName().replace('.', '/') + "$NativeProbe",
                "value",
                "()Ljava/lang/String;",
                stringType,
                List.of(),
                "entry",
                NativeBackend.AOT,
                false,
                true,
                Map.of("java.static", "true", "semanticContext", "jni")
        ).addBlock(entry);
        final NativeModule module = new NativeModule("explicit-zig-test").addFunction(function);

        final NativeCompilationResult result = new ExplicitZigNativeCompiler(
                new CanonicalLlvmIrEmitter(NativeStringProtection.fromBuildMaterial(
                        "explicit-zig-protected-test-material-v1".getBytes(StandardCharsets.UTF_8)
                ))).compile(
                module,
                Path.of(configured),
                temporary,
                Set.of(NativeTarget.WINDOWS_X86_64),
                "explicit-zig-test"
        );

        assertEquals(Set.of(NativeTarget.WINDOWS_X86_64), result.libraries().keySet());
        final Path library = result.libraries().get(NativeTarget.WINDOWS_X86_64);
        assertTrue(Files.size(library) > 0);
        new NativeLibraryValidator().validate(library, NativeTarget.WINDOWS_X86_64);
        final byte[] libraryBytes = Files.readAllBytes(library);
        assertFalse(contains(libraryBytes, SECRET_MARKER.getBytes(StandardCharsets.US_ASCII)));
        assertFalse(contains(libraryBytes, SECRET_MARKER.getBytes(StandardCharsets.UTF_16LE)));
        assertFalse(contains(libraryBytes, SECRET_MARKER.getBytes(StandardCharsets.UTF_16BE)));
        // Windows pins a loaded DLL until this test JVM exits, so load a disposable copy
        // outside JUnit's eagerly cleaned @TempDir.
        final Path runtimeCopy = Files.createTempFile("skid-native-runtime-", ".dll");
        Files.copy(library, runtimeCopy, StandardCopyOption.REPLACE_EXISTING);
        runtimeCopy.toFile().deleteOnExit();
        System.load(runtimeCopy.toAbsolutePath().toString());
        final String first = NativeProbe.value();
        assertEquals(EXPECTED, first);
        assertSame(NativeProbe.LITERAL, first);
        assertSame(first, NativeProbe.value());
        assertZeroAllocatedBytesAfterWarmup();
    }

    @Test
    void rejectsUnsupportedBodiesBeforeLaunchingTheDevelopmentCompiler() throws Exception {
        final var stringType = new NativeType.Reference("java/lang/String", false);
        final var block = new NativeBlock("entry")
                .addInstruction(new NativeInstruction.Operation("first", stringType,
                        NativeOpcode.STRING_CONSTANT, List.of(), Map.of("value", "one"), SourceLocation.UNKNOWN))
                .addInstruction(new NativeInstruction.Operation("second", stringType,
                        NativeOpcode.STRING_CONSTANT, List.of(), Map.of("value", "two"), SourceLocation.UNKNOWN))
                .terminate(new NativeTerminator.Return(new NativeOperand.Value("second", stringType)));
        final var function = new NativeFunction("unsupported", "sample/Strings", "value",
                "()Ljava/lang/String;", stringType, List.of(), "entry", NativeBackend.AOT,
                false, true, Map.of("java.static", "true", "semanticContext", "jni")).addBlock(block);
        final Path neverExecuted = Files.createFile(temporary.resolve("not-a-compiler.exe"));
        final Path output = temporary.resolve("no-output");
        final var failure = org.junit.jupiter.api.Assertions.assertThrows(NativeCompilationException.class,
                () -> new ExplicitZigNativeCompiler(new CanonicalLlvmIrEmitter()).compile(
                        new NativeModule("unsupported").addFunction(function), neverExecuted,
                        output, Set.of(NativeTarget.WINDOWS_X86_64), "unsupported-test"));
        assertTrue(failure.getMessage().contains("only a literal String return"));
        assertFalse(Files.exists(output), "Unsupported input must fail before any compiler output is staged");
    }

    private static void assertZeroAllocatedBytesAfterWarmup() {
        final java.lang.management.ThreadMXBean baseBean =
                java.lang.management.ManagementFactory.getThreadMXBean();
        assumeTrue(baseBean instanceof com.sun.management.ThreadMXBean,
                "Thread allocation accounting is unavailable");
        final com.sun.management.ThreadMXBean allocationBean =
                (com.sun.management.ThreadMXBean) baseBean;
        assumeTrue(allocationBean.isThreadAllocatedMemorySupported(),
                "Thread allocation accounting is unsupported");
        if (!allocationBean.isThreadAllocatedMemoryEnabled()) {
            allocationBean.setThreadAllocatedMemoryEnabled(true);
        }

        for (int index = 0; index < 100_000; index++) {
            NativeProbe.sink = NativeProbe.value();
        }
        final long threadId = Thread.currentThread().getId();
        final long before = allocationBean.getThreadAllocatedBytes(threadId);
        for (int index = 0; index < 100_000; index++) {
            NativeProbe.sink = NativeProbe.value();
        }
        final long allocated = allocationBean.getThreadAllocatedBytes(threadId) - before;
        assertEquals(0L, allocated, "cached native String return must not allocate Java heap objects");
    }

    private static boolean contains(final byte[] haystack, final byte[] needle) {
        if (needle.length == 0 || needle.length > haystack.length) return false;
        outer:
        for (int start = 0; start <= haystack.length - needle.length; start++) {
            for (int index = 0; index < needle.length; index++) {
                if (haystack[start + index] != needle[index]) continue outer;
            }
            return true;
        }
        return false;
    }

    private static final class NativeProbe {
        private static final String LITERAL = EXPECTED;
        private static volatile String sink;

        private static native String value();
    }
}
