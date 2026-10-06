package dev.skidfuscator.test.nativebackend;

import com.typesafe.config.ConfigFactory;
import dev.skidfuscator.config.DefaultSkidConfig;
import dev.skidfuscator.nativeir.*;
import dev.skidfuscator.obfuscator.Skidfuscator;
import dev.skidfuscator.obfuscator.nativebackend.key.NativeThreadedKeyFunction;
import dev.skidfuscator.obfuscator.nativebackend.key.NativeThreadedKeyRegistry;
import org.junit.jupiter.api.Test;
import org.mapleir.asm.ClassNode;
import org.mapleir.asm.MethodNode;
import org.mapleir.ir.code.expr.ConstantExpr;
import org.mapleir.ir.code.expr.invoke.StaticInvocationExpr;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.topdank.byteengineer.commons.data.JarContents;

import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class NativeThreadedKeyTest {
    @Test
    void reconstructsBothWidthsAndRemainsDependentOnTheIncomingSeed() {
        final Random values = new Random(0x5eed1234L);
        for (final NativeBackend backend : NativeBackend.values()) {
            for (final boolean wide : new boolean[]{false, true}) {
                for (int index = 0; index < 1000; index++) {
                    final long start = wide ? values.nextLong() : values.nextInt();
                    final long end = wide ? values.nextLong() : values.nextInt();
                    final NativeFunction function = NativeThreadedKeyFunction.create(
                            "key_" + index, "test/Keys", "key", backend, wide, start, end, new SecureRandom());
                    assertEquals(end, evaluate(function, start));
                    assertNotEquals(end, evaluate(function, start ^ 1L));
                    assertEquals(wide ? "(J)J" : "(I)I", function.javaDescriptor());
                    assertEquals(backend, function.backend());
                    assertEquals("true", function.metadata().get("java.static"));
                }
            }
        }
    }

    @Test
    void handlesZeroAndSignedOverflowBoundaries() {
        for (final boolean wide : new boolean[]{false, true}) {
            final long[] boundaries = wide
                    ? new long[]{0, 1, -1, Long.MIN_VALUE, Long.MAX_VALUE}
                    : new long[]{0, 1, -1, Integer.MIN_VALUE, Integer.MAX_VALUE};
            for (final long start : boundaries) {
                for (final long end : boundaries) {
                    final NativeFunction function = NativeThreadedKeyFunction.create(
                            "key", "test/Keys", "key", NativeBackend.VM, wide, start, end, new SecureRandom());
                    assertEquals(end, evaluate(function, start));
                }
            }
        }
    }

    @Test
    void stagesOnlySecretFreeCompanionsAndSealsTheHelperSet() {
        final Skidfuscator skid = mock(Skidfuscator.class);
        when(skid.getConfig()).thenReturn(new DefaultSkidConfig(ConfigFactory.parseString("""
                native { enabled = true, threadedKey { enabled = true, only = true, mode = VM } }
                """), ""));
        final JarContents contents = new JarContents();
        when(skid.getJarContents()).thenReturn(contents);
        final NativeThreadedKeyRegistry keys = new NativeThreadedKeyRegistry(skid);
        final ClassNode owner = new ClassNode();
        owner.node.name = "test/Application";
        final MethodNode method = new MethodNode(new org.objectweb.asm.tree.MethodNode(
                Opcodes.ACC_STATIC, "work", "()I", null, null), owner);
        owner.addMethod(method);
        final StaticInvocationExpr first = (StaticInvocationExpr) keys.reconstruct(
                method, false, 73, -27, new ConstantExpr(-27, Type.INT_TYPE));
        final StaticInvocationExpr second = (StaticInvocationExpr) keys.reconstruct(
                method, false, 73, -27, new ConstantExpr(-27, Type.INT_TYPE));
        assertEquals(first.getOwner(), second.getOwner());
        assertEquals(first.getName(), second.getName());
        assertEquals(1, keys.size());
        assertTrue(contents.getClassContents().isEmpty(), "Companions are not attached before commit");
        final var prepared = keys.seal();
        assertEquals(73, evaluate(prepared.get(0).function(), -27));
        assertEquals(2, prepared.get(0).method().node.instructions.size());
        assertEquals(Opcodes.ACONST_NULL, prepared.get(0).method().node.instructions.getFirst().getOpcode());
        assertEquals(Opcodes.ATHROW, prepared.get(0).method().node.instructions.getLast().getOpcode());
        assertFalse(method.isNative());
        assertEquals(1, keys.generatedCompanions().size());
        assertThrows(IllegalStateException.class, () -> keys.reconstruct(
                method, false, 74, -27, new ConstantExpr(-27, Type.INT_TYPE)));
        assertThrows(IllegalArgumentException.class, () -> keys.reconstruct(
                method, true, 73, -27, new ConstantExpr(-27, Type.INT_TYPE)));
    }

    private static long evaluate(final NativeFunction function, final long seed) {
        final boolean wide = function.returnType() == NativeType.Primitive.I64;
        final Map<String, Long> registers = new HashMap<>();
        registers.put("seed", wide ? seed : (int) seed);
        for (final NativeInstruction instruction : function.blocks().get(0).instructions()) {
            final NativeInstruction.Operation operation = (NativeInstruction.Operation) instruction;
            final long left = value(operation.operands().get(0), registers);
            final long right = value(operation.operands().get(1), registers);
            final long result = switch (operation.opcode()) {
                case BIT_XOR -> left ^ right;
                case ADD -> left + right;
                case MUL -> left * right;
                default -> throw new AssertionError(operation.opcode());
            };
            registers.put(operation.id(), wide ? result : (int) result);
        }
        final var terminator = (NativeTerminator.Return) function.blocks().get(0).terminator().orElseThrow();
        return value(terminator.value().orElseThrow(), registers);
    }

    private static long value(final NativeOperand operand, final Map<String, Long> registers) {
        return operand instanceof NativeOperand.Value variable ? registers.get(variable.id())
                : ((Number) ((NativeOperand.Constant) operand).value()).longValue();
    }
}
