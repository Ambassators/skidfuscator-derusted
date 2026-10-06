package dev.skidfuscator.test.nativebackend;

import dev.skidfuscator.nativeir.*;
import dev.skidfuscator.nativetoolchain.VmProtectionSettings;
import dev.skidfuscator.nativetoolchain.vm.*;
import dev.skidfuscator.obfuscator.nativebackend.key.NativeThreadedKeyFunction;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/** Real-JVM tests for the complete native runtime; test DLL is never a production artifact. */
public class NativeVmJniTest {
    private static native long invokeBits(byte[] program, byte[] key, long[] values, Object[] references, int width);
    private static native Object invokeObject(byte[] program, byte[] key, long[] values, Object[] references);
    private static final Object[] NO_REFERENCES = new Object[0];

    @BeforeAll
    static void loadTestLibrary() {
        final String configured = System.getenv("SKID_VM_TEST_LIBRARY");
        assumeTrue(configured != null && !configured.isBlank(), "Set SKID_VM_TEST_LIBRARY for real-JVM tests");
        final Path library = Path.of(configured).toAbsolutePath();
        assertTrue(Files.isRegularFile(library), "Configured native JNI test library is missing");
        System.load(library.toString());
    }

    @Test
    void executesKeyHelpersConcurrentlyOnRealJvmThreads() throws Exception {
        final var pool = Executors.newFixedThreadPool(6);
        try {
            final List<Callable<Void>> tasks = new ArrayList<>();
            for (int task = 0; task < 12; task++) {
                final int index = task;
                tasks.add(() -> {
                    final boolean wide = index % 2 == 0;
                    final long start = wide ? Long.MIN_VALUE + index : Integer.MIN_VALUE + index;
                    final long end = wide ? Long.MAX_VALUE - index : Integer.MAX_VALUE - index;
                    final var program = compile(NativeThreadedKeyFunction.create("key", "sample/Keys", "key",
                            NativeBackend.VM, wide, start, end, new SecureRandom()));
                    final byte[] bytes = new VmProgramCodec().encode(program);
                    final byte[] key = VmBytecodeCompiler.reassembleKey(program.keyFragments());
                    try {
                        for (int iteration = 0; iteration < 100; iteration++)
                            assertEquals(end, invokeBits(bytes, key, new long[]{start}, NO_REFERENCES, wide ? 8 : 4));
                    } finally { Arrays.fill(key, (byte) 0); }
                    return null;
                });
            }
            for (final var future : pool.invokeAll(tasks, 60, TimeUnit.SECONDS)) future.get();
        } finally { pool.shutdownNow(); }
    }

    @Test
    void propagatesRealJavaArithmeticExceptions() {
        final var type = NativeType.Primitive.I32;
        final var function = function(type, "(II)I", List.of(
                new NativeParameter("a", type, 0), new NativeParameter("b", type, 1)))
                .addBlock(new NativeBlock("entry").addInstruction(new NativeInstruction.Operation(
                        "quotient", type, NativeOpcode.SDIV, List.of(
                        new NativeOperand.Value("a", type), new NativeOperand.Value("b", type))))
                        .terminate(new NativeTerminator.Return(new NativeOperand.Value("quotient", type))));
        final var program = compile(function);
        assertThrows(ArithmeticException.class, () -> callBits(program, 4, NO_REFERENCES, 5, 0));
        assertEquals(7, callBits(program, 4, NO_REFERENCES, 21, 3));
    }

    @Test
    void catchesExplicitThrowAndPreservesThrowableIdentity() {
        final var ref = new NativeType.Reference("java/lang/Throwable", true);
        final var function = function(ref, "(Ljava/lang/Throwable;)Ljava/lang/Throwable;",
                List.of(new NativeParameter("argument", ref, 0)));
        function.addBlock(new NativeBlock("entry")
                .addExceptionEdge(new NativeExceptionEdge("handler", Optional.of("java/lang/Throwable"), 0))
                .terminate(new NativeTerminator.Throw(new NativeOperand.Value("argument", ref))));
        function.addBlock(new NativeBlock("handler")
                .addInstruction(new NativeInstruction.Operation("caught", ref, NativeOpcode.CATCH_EXCEPTION, List.of()))
                .terminate(new NativeTerminator.Return(new NativeOperand.Value("caught", ref))));
        final var program = compile(function);
        final IllegalStateException failure = new IllegalStateException("same object");
        assertSame(failure, callObject(program, new Object[]{failure}));
        assertInstanceOf(NullPointerException.class, callObject(program, new Object[]{null}));
    }

    @Test
    void comparesObjectIdentityRatherThanJniLocalHandleAddresses() {
        final var ref = new NativeType.Reference("java/lang/Object", true);
        final var type = NativeType.Primitive.I1;
        final var function = function(type, "(Ljava/lang/Object;Ljava/lang/Object;)Z", List.of(
                new NativeParameter("left", ref, 0), new NativeParameter("right", ref, 1)))
                .addBlock(new NativeBlock("entry").addInstruction(new NativeInstruction.Operation(
                        "same", type, NativeOpcode.ICMP_EQ, List.of(new NativeOperand.Value("left", ref),
                        new NativeOperand.Value("right", ref))))
                        .terminate(new NativeTerminator.Return(new NativeOperand.Value("same", type))));
        final var program = compile(function);
        final Object shared = new Object();
        assertEquals(1, callBits(program, 1, new Object[]{shared, shared}));
        assertEquals(0, callBits(program, 1, new Object[]{shared, new Object()}));
        assertEquals(1, callBits(program, 1, new Object[]{null, null}));
    }

    @Test
    void tamperingThrowsARealSecurityException() {
        final var program = compile(NativeThreadedKeyFunction.create("key", "sample/Keys", "key",
                NativeBackend.VM, false, 27, 73, new SecureRandom()));
        final byte[] bytes = new VmProgramCodec().encode(program);
        final byte[] key = VmBytecodeCompiler.reassembleKey(program.keyFragments());
        try {
            bytes[bytes.length - 1] ^= 1;
            assertThrows(SecurityException.class, () -> invokeBits(bytes, key, new long[]{27}, NO_REFERENCES, 4));
        } finally { Arrays.fill(key, (byte) 0); }
    }

    @Test
    void unauthenticatedHaltPoliciesFailAsExceptionsWithoutTerminatingTheJvm() {
        for (final var response : List.of(VmProtectionSettings.Response.HALT,
                VmProtectionSettings.Response.DELAYED_HALT)) {
            final var policy = new VmProtectionSettings(VmProtectionSettings.Profile.STANDARD, response,
                    true, false, false, false, true, 2, 16, 32,
                    response == VmProtectionSettings.Response.DELAYED_HALT ? 250 : 0);
            final var helper = NativeThreadedKeyFunction.create("key", "sample/Keys", "key",
                    NativeBackend.VM, false, 27, 73, new SecureRandom());
            final var program = new VmBytecodeCompiler().compile(new NativeModule("policy-test")
                    .addFunction(helper), "policy-test", new SecureRandom(), policy);
            final byte[] bytes = new VmProgramCodec().encode(program);
            final byte[] key = VmBytecodeCompiler.reassembleKey(program.keyFragments());
            try {
                assertEquals(73, invokeBits(bytes, key, new long[]{27}, NO_REFERENCES, 4));
                bytes[bytes.length - 1] ^= 1;
                assertThrows(SecurityException.class,
                        () -> invokeBits(bytes, key, new long[]{27}, NO_REFERENCES, 4));
            } finally { Arrays.fill(key, (byte) 0); }
        }
    }

    @Test
    void cachePolicyDoesNotChangeKeySemanticsOrLeakStateBetweenInvocations() {
        for (final int entries : new int[]{0, 1, 32, 4096}) {
            final var policy = new VmProtectionSettings(VmProtectionSettings.Profile.STANDARD,
                    VmProtectionSettings.Response.THROW, true, false, false, false,
                    true, 2, 16, entries, 0);
            final var helper = NativeThreadedKeyFunction.create("key", "sample/Keys", "key",
                    NativeBackend.VM, true, Long.MIN_VALUE, Long.MAX_VALUE, new SecureRandom());
            final var program = new VmBytecodeCompiler().compile(new NativeModule("cache-test")
                    .addFunction(helper), "cache-test", new SecureRandom(), policy);
            for (int invocation = 0; invocation < 20; invocation++) {
                assertEquals(Long.MAX_VALUE, callBits(program, 8, NO_REFERENCES, Long.MIN_VALUE));
                assertNotEquals(Long.MAX_VALUE, callBits(program, 8, NO_REFERENCES, Long.MIN_VALUE + 1));
            }
        }
    }

    private static NativeFunction function(NativeType result, String descriptor, List<NativeParameter> parameters) {
        return new NativeFunction("function", "sample/Function", "function", descriptor, result, parameters,
                "entry", NativeBackend.VM, false, true, Map.of("java.static", "true"));
    }
    private static VmProgram compile(NativeFunction function) {
        return new VmBytecodeCompiler().compile(new NativeModule("jni-test").addFunction(function),
                "native-jni-test", new SecureRandom(), VmProtectionSettings.standard());
    }
    private static long callBits(VmProgram program, int width, Object[] references, long... arguments) {
        final byte[] key = VmBytecodeCompiler.reassembleKey(program.keyFragments());
        try { return invokeBits(new VmProgramCodec().encode(program), key, arguments, references, width); }
        finally { Arrays.fill(key, (byte) 0); }
    }
    private static Object callObject(VmProgram program, Object[] references, long... arguments) {
        final byte[] key = VmBytecodeCompiler.reassembleKey(program.keyFragments());
        try { return invokeObject(new VmProgramCodec().encode(program), key, arguments, references); }
        finally { Arrays.fill(key, (byte) 0); }
    }
}
