package dev.skidfuscator.obfuscator.nativebackend;

import dev.skidfuscator.nativeir.*;
import java.util.HashMap;
import java.util.Map;

/** Reviewed detector state/encoding replacement with no surviving Java implementation owner. */
final class CppClientDetectionRegion {
    static final Map<String, String> DESCRIPTORS = Map.of(
            "install", "(Ljava/lang/ClassLoader;)V", "capture", "(J)[[B", "shutdown", "()V");

    static NativeFunction replace(NativeFunction source, String kind) {
        if (!source.javaDescriptor().equals(DESCRIPTORS.get(kind)) || source.backend() != NativeBackend.AOT
                || source.synchronizedMethod() || !"true".equals(source.metadata().get("java.static")))
            throw new NativeBackendUnavailableException("Unsupported C++ client detection boundary: " + kind);
        var metadata = new HashMap<>(source.metadata());
        metadata.put("cpp.client.detection", kind);
        metadata.put("cpp.java.owner", "elided-client-detection-v1");
        var function = new NativeFunction(source.symbol(), source.javaOwner(), source.javaName(), source.javaDescriptor(),
                source.returnType(), source.parameters(), "cpp.entry", NativeBackend.AOT, false, true, metadata);
        NativeBlock block = new NativeBlock("cpp.entry");
        return function.addBlock(block.terminate(source.returnType().isVoid() ? NativeTerminator.Return.voidReturn()
                : new NativeTerminator.Return(new NativeOperand.Constant(source.returnType(), null))));
    }
}
