package dev.skidfuscator.test.nativebackend;

import dev.skidfuscator.nativeir.*;
import dev.skidfuscator.nativetoolchain.VmProtectionSettings;
import dev.skidfuscator.nativetoolchain.vm.*;
import dev.skidfuscator.obfuscator.nativebackend.key.NativeThreadedKeyFunction;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/** Executes real encrypted Java-produced programs in SkidLLVM's C++ runtime.
 * Set SKID_VM_TEST_EXECUTABLE to the CMake-built skid-vm-program-probe executable.
 * The probe uses a test JNI interface; it does not substitute for JVM/platform smoke tests.
 */
class NativeVmInteropTest {
    @TempDir Path directory;
    private Path executable;
    private int fixture;

    @BeforeEach
    void requireNativeProbe() {
        final String configured = System.getenv("SKID_VM_TEST_EXECUTABLE");
        assumeTrue(configured != null && !configured.isBlank(), "Set SKID_VM_TEST_EXECUTABLE for native interoperability");
        executable = Path.of(configured);
        assertTrue(Files.isRegularFile(executable), "Configured native test executable does not exist");
    }

    @Test
    void executesNativeKeyHelpersAtBothWidthsAndPreservesReturnGuards() throws Exception {
        final Random random = new Random(483927L);
        for (final boolean wide : new boolean[]{false, true}) {
            for (int index = 0; index < 20; index++) {
                final long start = wide ? random.nextLong() : random.nextInt();
                final long end = wide ? random.nextLong() : random.nextInt();
                final var function = NativeThreadedKeyFunction.create("key", "sample/Key", "key",
                        NativeBackend.VM, wide, start, end, new SecureRandom());
                final var program = compile(function, VmProtectionSettings.standard());
                final var result = run(program, wide ? 8 : 4, start);
                assertEquals(0, result.status());
                assertEquals(wide ? end : Integer.toUnsignedLong((int) end), result.bits());
                assertEquals("none", result.exception());
                assertNotEquals(result.bits(), run(program, wide ? 8 : 4, start ^ 1).bits());
            }
        }
    }

    @Test
    void preservesSignedWideningAndFloatingPointConversions() throws Exception {
        final var wide = conversion(NativeType.Primitive.I32, NativeType.Primitive.I64, "(I)J");
        assertEquals(-1L, run(compile(wide, VmProtectionSettings.standard()), 8, 0xffffffffL).bits());
        final var toDouble = conversion(NativeType.Primitive.F32, NativeType.Primitive.F64, "(F)D");
        assertEquals(Double.doubleToRawLongBits(-12.5), run(compile(toDouble, VmProtectionSettings.standard()),
                8, Integer.toUnsignedLong(Float.floatToRawIntBits(-12.5f))).bits());
        final var toFloat = conversion(NativeType.Primitive.F64, NativeType.Primitive.F32, "(D)F");
        assertEquals(Integer.toUnsignedLong(Float.floatToRawIntBits(7.25f)), run(
                compile(toFloat, VmProtectionSettings.standard()), 4, Double.doubleToRawLongBits(7.25)).bits());
    }

    @Test
    void matchesNegativeSwitchCases() throws Exception {
        final var type = NativeType.Primitive.I32;
        final var function = function(type, "(I)I", List.of(new NativeParameter("arg", type, 0)));
        function.addBlock(new NativeBlock("entry").terminate(new NativeTerminator.Switch(
                new NativeOperand.Value("arg", type), Map.of(-1L, "negative"), "fallback", SourceLocation.UNKNOWN)));
        function.addBlock(new NativeBlock("negative").terminate(new NativeTerminator.Return(new NativeOperand.Constant(type, 73))));
        function.addBlock(new NativeBlock("fallback").terminate(new NativeTerminator.Return(new NativeOperand.Constant(type, 19))));
        final var program = compile(function, VmProtectionSettings.standard());
        assertEquals(73, run(program, 4, 0xffffffffL).bits());
        assertEquals(19, run(program, 4, 1).bits());
    }

    @Test
    void javaExceptionsDoNotTriggerTheHaltPolicy() throws Exception {
        final var type = NativeType.Primitive.I32;
        final var function = function(type, "(II)I", List.of(
                new NativeParameter("a", type, 0), new NativeParameter("b", type, 1)));
        function.addBlock(new NativeBlock("entry").addInstruction(new NativeInstruction.Operation(
                "quotient", type, NativeOpcode.SDIV, List.of(
                new NativeOperand.Value("a", type), new NativeOperand.Value("b", type))))
                .terminate(new NativeTerminator.Return(new NativeOperand.Value("quotient", type))));
        final var policy = new VmProtectionSettings(VmProtectionSettings.Profile.STANDARD,
                VmProtectionSettings.Response.HALT, true, false, false, false, true, 2, 0, 0, 0);
        final var result = run(compile(function, policy), 4, 5, 0);
        assertEquals(-20, result.status());
        assertEquals("java/lang/ArithmeticException", result.exception());
    }

    @Test
    void explicitThrowReachesItsExceptionHandler() throws Exception {
        final var type = NativeType.Primitive.I32;
        final var ref = new NativeType.Reference("java/lang/Throwable", true);
        final var function = function(type, "()I", List.of());
        function.addBlock(new NativeBlock("entry")
                .addExceptionEdge(new NativeExceptionEdge("handler", Optional.empty(), 0))
                .terminate(new NativeTerminator.Throw(new NativeOperand.Constant(ref, null))));
        function.addBlock(new NativeBlock("handler")
                .addInstruction(new NativeInstruction.Operation("caught", ref, NativeOpcode.CATCH_EXCEPTION, List.of()))
                .terminate(new NativeTerminator.Return(new NativeOperand.Constant(type, 91))));
        final var result = run(compile(function, VmProtectionSettings.standard()), 4);
        assertEquals(0, result.status());
        assertEquals(91, result.bits());
        assertEquals("none", result.exception());
    }

    @Test
    void rejectsTamperedCiphertextAndTruncatedHeaders() throws Exception {
        final var function = NativeThreadedKeyFunction.create("key", "sample/Key", "key",
                NativeBackend.VM, false, 27, 73, new SecureRandom());
        final var program = compile(function, VmProtectionSettings.standard());
        final byte[] bytes = new VmProgramCodec().encode(program);
        final byte[] tampered = bytes.clone();
        tampered[tampered.length - 1] ^= 1;
        final var changed = runBytes(program, tampered, 4, 27);
        assertNotEquals(0, changed.status());
        assertEquals("java/lang/SecurityException", changed.exception());
        final var truncated = runBytes(program, Arrays.copyOf(bytes, 9), 4, 27);
        assertNotEquals(0, truncated.status());
        assertEquals("java/lang/SecurityException", truncated.exception());
    }

    private NativeFunction conversion(NativeType from, NativeType to, String descriptor) {
        return function(to, descriptor, List.of(new NativeParameter("arg", from, 0)))
                .addBlock(new NativeBlock("entry").addInstruction(new NativeInstruction.Operation(
                        "converted", to, NativeOpcode.CONVERT, List.of(new NativeOperand.Value("arg", from)),
                        Map.of("signed", "true"), SourceLocation.UNKNOWN))
                        .terminate(new NativeTerminator.Return(new NativeOperand.Value("converted", to))));
    }

    private NativeFunction function(NativeType result, String descriptor, List<NativeParameter> parameters) {
        return new NativeFunction("function", "sample/Function", "function", descriptor, result, parameters,
                "entry", NativeBackend.VM, false, true, Map.of("java.static", "true"));
    }

    private VmProgram compile(NativeFunction function, VmProtectionSettings policy) {
        return new VmBytecodeCompiler().compile(new NativeModule("interop").addFunction(function),
                "native-interop", new SecureRandom(), policy);
    }

    private Result run(VmProgram program, int width, long... arguments) throws Exception {
        return runBytes(program, new VmProgramCodec().encode(program), width, arguments);
    }

    private Result runBytes(VmProgram program, byte[] bytes, int width, long... arguments) throws Exception {
        final Path payload = directory.resolve("program-" + fixture + ".skvm");
        final Path key = directory.resolve("key-" + fixture + ".bin");
        final Path log = directory.resolve("probe-" + fixture++ + ".log");
        Files.write(payload, bytes);
        Files.write(key, VmBytecodeCompiler.reassembleKey(program.keyFragments()));
        final List<String> command = new ArrayList<>(List.of(executable.toString(), payload.toString(),
                key.toString(), "0", Integer.toString(width)));
        for (long argument : arguments) command.add(Long.toUnsignedString(argument));
        final Process process = new ProcessBuilder(command).redirectErrorStream(true).redirectOutput(log.toFile()).start();
        try {
            assertTrue(process.waitFor(15, TimeUnit.SECONDS), "Native probe exceeded the test timeout");
            final String output = Files.readString(log, StandardCharsets.UTF_8).trim();
            assertEquals(0, process.exitValue(), output);
            final String[] parts = output.split("\\s+");
            assertEquals(3, parts.length, output);
            return new Result(Integer.parseInt(parts[0].substring("status=".length())),
                    Long.parseUnsignedLong(parts[1].substring("result=".length())),
                    parts[2].substring("exception=".length()));
        } finally {
            if (process.isAlive()) process.destroyForcibly();
            Files.deleteIfExists(key);
        }
    }

    private record Result(int status, long bits, String exception) {}
}
