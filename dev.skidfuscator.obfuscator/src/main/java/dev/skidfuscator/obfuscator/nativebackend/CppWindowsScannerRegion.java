package dev.skidfuscator.obfuscator.nativebackend;

import dev.skidfuscator.nativeir.*;
import java.util.HashMap;
import java.util.Map;

/** Reviewed current-JVM Windows scanner replacement; its Java owner is not initialized. */
final class CppWindowsScannerRegion {
    static final String OWNER = "com/orbitclient/orbitclient/util/vape/IsolatedJnaRuntime";
    static final Map<String,String> METHODS = Map.of(
            "scanCurrentProcess()Ljava/util/List;", "current",
            "scanSlinkyModules()Ljava/util/List;", "modules",
            "readSlinkyImage(IJJ)Ljava/util/List;", "image",
            "readSlinkyImage(IJJ[J)Ljava/util/List;", "ranges");

    static NativeFunction replace(NativeFunction source) {
        String kind = METHODS.get(source.javaName() + source.javaDescriptor());
        if (kind == null || !OWNER.equals(source.javaOwner()) || source.backend()!=NativeBackend.AOT
                || source.synchronizedMethod() || !"true".equals(source.metadata().get("java.static")))
            throw new NativeBackendUnavailableException("Unsupported C++ Windows scanner boundary");
        var metadata = new HashMap<>(source.metadata());
        metadata.put("cpp.windows.scanner", kind);
        metadata.put("cpp.java.owner", "elided-current-jvm-scanner-v1");
        var function = new NativeFunction(source.symbol(),source.javaOwner(),source.javaName(),source.javaDescriptor(),
                source.returnType(),source.parameters(),"cpp.entry",NativeBackend.AOT,false,true,metadata);
        return function.addBlock(new NativeBlock("cpp.entry").terminate(new NativeTerminator.Return(
                new NativeOperand.Constant(source.returnType(),null))));
    }
}
