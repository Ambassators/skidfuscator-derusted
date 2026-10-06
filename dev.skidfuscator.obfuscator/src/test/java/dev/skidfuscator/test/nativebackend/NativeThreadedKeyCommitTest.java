package dev.skidfuscator.test.nativebackend;

import com.typesafe.config.ConfigFactory;
import dev.skidfuscator.config.DefaultSkidConfig;
import dev.skidfuscator.nativetoolchain.NativeTarget;
import dev.skidfuscator.obfuscator.Skidfuscator;
import dev.skidfuscator.obfuscator.nativebackend.artifact.NativeCompilationInstaller;
import dev.skidfuscator.obfuscator.nativebackend.commit.NativeMethodCommitTransaction;
import dev.skidfuscator.obfuscator.nativebackend.key.NativeThreadedKeyRegistry;
import dev.skidfuscator.obfuscator.nativebackend.runtime.NativeLoaderGenerator;
import dev.skidfuscator.obfuscator.nativebackend.runtime.NativeLoaderSpec;
import org.junit.jupiter.api.Test;
import org.mapleir.asm.ClassHelper;
import org.mapleir.asm.MethodNode;
import org.mapleir.ir.code.expr.ConstantExpr;
import org.mapleir.ir.code.expr.invoke.StaticInvocationExpr;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.topdank.byteengineer.commons.data.JarClassData;
import org.topdank.byteengineer.commons.data.JarContents;

import java.util.List;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/** Verifies the Java installation boundary independently of native compilation.
 * The loader metadata below is a fixture; this test never loads a fixture DLL.
 */
class NativeThreadedKeyCommitTest {
    @Test
    void committingKeyHelpersLeavesApplicationBytecodeUnchanged() throws Exception {
        final var skid = mock(Skidfuscator.class);
        when(skid.getConfig()).thenReturn(new DefaultSkidConfig(ConfigFactory.parseString("""
                native { enabled = true, threadedKey { enabled = true, only = true, mode = VM } }
                """), ""));
        final var contents = new JarContents();
        when(skid.getJarContents()).thenReturn(contents);
        final var raw = new org.objectweb.asm.tree.ClassNode();
        raw.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER,
                "sample/KeyOnlyApplication", null, "java/lang/Object", null);
        final var owner = ClassHelper.create(raw);
        final var application = new MethodNode(new org.objectweb.asm.tree.MethodNode(
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "work", "()I", null, null), owner);
        owner.addMethod(application);
        final var keys = new NativeThreadedKeyRegistry(skid);
        final var invocation = (StaticInvocationExpr) keys.reconstruct(application, false,
                73, 27, new ConstantExpr(27, Type.INT_TYPE));
        application.node.instructions.add(new IntInsnNode(Opcodes.BIPUSH, 27));
        application.node.instructions.add(new MethodInsnNode(Opcodes.INVOKESTATIC,
                invocation.getOwner(), invocation.getName(), "(I)I", false));
        application.node.instructions.add(new InsnNode(Opcodes.IRETURN));
        final byte[] before = ClassHelper.toByteArray(owner, ClassWriter.COMPUTE_MAXS);
        contents.getClassContents().add(new JarClassData(owner.getName() + ".class", before, owner));
        final var prepared = keys.seal();
        contents.getClassContents().addAll(keys.generatedCompanions());
        final var library = new NativeLoaderSpec.Library(NativeTarget.WINDOWS_X86_64,
                "META-INF/skidfuscator/native/key-commit/windows-x86_64/key.dll",
                "a".repeat(64), "key.dll", 1);
        final var loader = new NativeLoaderGenerator().generate(new NativeLoaderSpec(
                "sample/runtime/KeyLoader", "key-commit",
                NativeCompilationInstaller.manifestResourcePath("key-commit"),
                "b".repeat(64), 1, Map.of(NativeTarget.WINDOWS_X86_64, library)));
        new NativeMethodCommitTransaction().commit(contents, loader,
                prepared.stream().<NativeMethodCommitTransaction.Mutation>map(
                        helper -> new NativeMethodCommitTransaction.Direct(helper.method())).toList(),
                jar -> List.of());

        assertArrayEquals(before, ClassHelper.toByteArray(owner, ClassWriter.COMPUTE_MAXS));
        assertFalse(application.isNative());
        assertFalse(owner.getMethods().stream().anyMatch(MethodNode::isClinit));
        assertEquals(1, prepared.size());
        final var helper = prepared.get(0).method();
        assertTrue(helper.isNative());
        assertEquals(0, helper.node.instructions.size());
        final var initializer = helper.owner.getMethods().stream()
                .filter(MethodNode::isClinit).findFirst().orElseThrow();
        final var call = assertInstanceOf(MethodInsnNode.class, initializer.node.instructions.getFirst());
        assertEquals(loader.internalName(), call.owner);
        final var serialized = ClassHelper.create(ClassHelper.toByteArray(helper.owner, ClassWriter.COMPUTE_MAXS));
        assertTrue(serialized.getMethods().stream().anyMatch(method -> method.getName().equals(helper.getName())
                && method.isNative() && method.node.instructions.size() == 0));
    }
}
