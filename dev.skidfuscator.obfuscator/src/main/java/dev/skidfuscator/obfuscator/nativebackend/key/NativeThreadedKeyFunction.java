package dev.skidfuscator.obfuscator.nativebackend.key;

import dev.skidfuscator.nativeir.NativeBackend;
import dev.skidfuscator.nativeir.NativeBlock;
import dev.skidfuscator.nativeir.NativeFunction;
import dev.skidfuscator.nativeir.NativeInstruction;
import dev.skidfuscator.nativeir.NativeOpcode;
import dev.skidfuscator.nativeir.NativeOperand;
import dev.skidfuscator.nativeir.NativeParameter;
import dev.skidfuscator.nativeir.NativeTerminator;
import dev.skidfuscator.nativeir.NativeType;

import java.security.SecureRandom;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Builds a word-width-preserving seed reconstruction function directly in native IR.
 * No equivalent Java body or Java-side adjustment constant is generated.
 * This is reversible obfuscation, not a cryptographic key-storage primitive.
 */
public final class NativeThreadedKeyFunction {
    private NativeThreadedKeyFunction() {
    }

    public static NativeFunction create(
            final String symbol,
            final String owner,
            final String name,
            final NativeBackend backend,
            final boolean wide,
            final long starting,
            final long outcome,
            final SecureRandom random
    ) {
        Objects.requireNonNull(random, "random");
        final NativeType.Primitive type = wide ? NativeType.Primitive.I64 : NativeType.Primitive.I32;
        final long salt = narrow(random.nextLong(), wide);
        // Multiplication by an odd word is a bijection modulo 2^32 or 2^64.
        final long multiplier = narrow(random.nextLong() | 1L, wide);
        final long offset = narrow(random.nextLong(), wide);
        final long correction = narrow(((starting ^ salt) * multiplier + offset) ^ outcome, wide);
        final NativeBlock block = new NativeBlock("entry");
        block.addInstruction(operation("masked", type, NativeOpcode.BIT_XOR,
                new NativeOperand.Value("seed", type), constant(type, salt)));
        block.addInstruction(operation("scaled", type, NativeOpcode.MUL,
                new NativeOperand.Value("masked", type), constant(type, multiplier)));
        block.addInstruction(operation("shifted", type, NativeOpcode.ADD,
                new NativeOperand.Value("scaled", type), constant(type, offset)));
        block.addInstruction(operation("result", type, NativeOpcode.BIT_XOR,
                new NativeOperand.Value("shifted", type), constant(type, correction)));
        block.terminate(new NativeTerminator.Return(new NativeOperand.Value("result", type)));
        return new NativeFunction(symbol, owner, name, wide ? "(J)J" : "(I)I", type,
                List.of(new NativeParameter("seed", type, 0)), "entry", backend,
                false, false, Map.of("java.static", "true")).addBlock(block);
    }

    private static long narrow(final long value, final boolean wide) {
        return wide ? value : (int) value;
    }

    private static NativeOperand.Constant constant(final NativeType.Primitive type, final long value) {
        // Separate branches avoid the conditional operator promoting boxed Integer to Long.
        if (type == NativeType.Primitive.I32) {
            return new NativeOperand.Constant(type, (int) value);
        }
        return new NativeOperand.Constant(type, value);
    }

    private static NativeInstruction.Operation operation(
            final String name,
            final NativeType type,
            final NativeOpcode opcode,
            final NativeOperand left,
            final NativeOperand right
    ) {
        return new NativeInstruction.Operation(name, type, opcode, List.of(left, right));
    }
}
