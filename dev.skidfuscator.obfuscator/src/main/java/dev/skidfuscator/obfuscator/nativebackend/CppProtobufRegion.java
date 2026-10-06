package dev.skidfuscator.obfuscator.nativebackend;

import dev.skidfuscator.nativeir.*;
import java.util.HashMap;
import java.util.List;

/** Explicit, byte-array-bounded protobuf region; no native message is a JVM reference. */
final class CppProtobufRegion {
    static final String DESCRIPTOR = "(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;J[[B)[B";

    static NativeFunction replace(NativeFunction source) {
        if (source.backend() != NativeBackend.AOT || source.synchronizedMethod()
                || !"true".equals(source.metadata().get("java.static"))
                || !DESCRIPTOR.equals(source.javaDescriptor()))
            throw new NativeBackendUnavailableException("C++ protobuf batch region has an unsupported ABI");
        var metadata = new HashMap<>(source.metadata());
        metadata.put("cpp.protobuf.kernel", "bulk-batch-v1");
        var function = new NativeFunction(source.symbol(), source.javaOwner(), source.javaName(),
                source.javaDescriptor(), source.returnType(), source.parameters(), "cpp.entry",
                source.backend(), false, true, metadata);
        // This body is replaced by the capability-checked LLVM lowering before code generation.
        function.addBlock(new NativeBlock("cpp.entry").terminate(new NativeTerminator.Return(
                new NativeOperand.Constant(source.returnType(), null))));
        return function;
    }

    static boolean calls(NativeFunction caller, NativeFunction target) {
        return caller.backend() == NativeBackend.AOT && caller.blocks().stream()
                .flatMap(b -> b.instructions().stream()).filter(NativeInstruction.Operation.class::isInstance)
                .map(NativeInstruction.Operation.class::cast)
                .anyMatch(op -> op.opcode() == NativeOpcode.JAVA_CALL
                        && target.javaOwner().equals(op.attributes().get("owner"))
                        && target.javaName().equals(op.attributes().get("name"))
                        && target.javaDescriptor().equals(op.attributes().get("descriptor"))
                        && "static".equals(op.attributes().get("invoke")));
    }
}
