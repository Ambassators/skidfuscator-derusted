package dev.skidfuscator.test.nativebackend.commit;

import dev.skidfuscator.nativetoolchain.NativeTarget;
import dev.skidfuscator.obfuscator.nativebackend.commit.NativeMethodCommitTransaction;
import dev.skidfuscator.obfuscator.nativebackend.runtime.NativeLoaderGenerator;
import dev.skidfuscator.obfuscator.nativebackend.runtime.NativeLoaderSpec;
import org.junit.jupiter.api.Test;
import org.mapleir.asm.ClassHelper;
import org.mapleir.asm.ClassNode;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.FrameNode;
import org.objectweb.asm.tree.InsnNode;
import org.topdank.byteengineer.commons.data.JarClassData;
import org.topdank.byteengineer.commons.data.JarContents;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.*;

class NativeLoaderFramePreservationTest {
    @Test void committedLoaderRetainsFramesThroughExemptSerialization() throws Exception {
        var asm = new org.objectweb.asm.tree.ClassNode();
        asm.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER,
                "fixture/NativeTarget", null, "java/lang/Object", null);
        var method = new org.objectweb.asm.tree.MethodNode(
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "value", "()I", null, null);
        method.instructions.add(new InsnNode(Opcodes.ICONST_1));
        method.instructions.add(new InsnNode(Opcodes.IRETURN));
        method.maxStack = 1;
        asm.methods.add(method);
        ClassNode owner = ClassHelper.create(asm);
        JarContents contents = new JarContents();
        contents.getClassContents().add(new JarClassData(owner.getName() + ".class",
                ClassHelper.toByteArray(owner, ClassWriter.COMPUTE_MAXS), owner));
        String loaderName = "fixture/GeneratedNativeLoader";
        var library = new NativeLoaderSpec.Library(NativeTarget.WINDOWS_X86_64,
                "META-INF/skidfuscator/native/test/windows-x86_64/test.dll",
                "a".repeat(64), "test.dll", 1);
        var loader = new NativeLoaderGenerator().generate(new NativeLoaderSpec(
                loaderName, "test", "META-INF/skidfuscator/native/test/manifest.properties",
                "b".repeat(64), 1, Map.of(NativeTarget.WINDOWS_X86_64, library)));
        new NativeMethodCommitTransaction().commit(contents, loader,
                List.of(new NativeMethodCommitTransaction.Direct(owner.getMethods().get(0))),
                ignored -> List.of());
        ClassNode committed = contents.getClassContents().stream().map(JarClassData::getClassNode)
                .filter(node -> loaderName.equals(node.getName())).findFirst().orElseThrow();
        assertTrue(committed.node.methods.stream().flatMap(m -> Arrays.stream(m.instructions.toArray()))
                .anyMatch(FrameNode.class::isInstance), "Post-dump loader insertion must not strip stack maps");
        byte[] bytes = ClassHelper.toByteArray(committed, 0);
        Class<?> type = new Loader().define(bytes);
        var constructor = type.getDeclaredConstructor();
        constructor.setAccessible(true);
        assertNotNull(constructor.newInstance(), "Verify all generated Java 8 bytecode without loading a DLL");
    }
    private static final class Loader extends ClassLoader {
        Class<?> define(byte[] bytes) { return defineClass(null, bytes, 0, bytes.length); }
    }
}
