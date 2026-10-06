package dev.skidfuscator.test.nativebackend.commit;

import dev.skidfuscator.nativetoolchain.NativeTarget;
import dev.skidfuscator.obfuscator.nativebackend.artifact.NativeCompilationInstaller;
import dev.skidfuscator.obfuscator.nativebackend.commit.NativeMethodCommitTransaction;
import dev.skidfuscator.obfuscator.nativebackend.JavaLinkageHelper;
import dev.skidfuscator.obfuscator.nativebackend.runtime.NativeLoaderGenerator;
import dev.skidfuscator.obfuscator.nativebackend.runtime.NativeLoaderSpec;
import org.junit.jupiter.api.Test;
import org.mapleir.asm.ClassHelper;
import org.mapleir.asm.ClassNode;
import org.mapleir.asm.MethodNode;
import org.objectweb.asm.Attribute;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.VarInsnNode;
import org.topdank.byteengineer.commons.data.JarClassData;
import org.topdank.byteengineer.commons.data.JarContents;
import org.topdank.byteengineer.commons.data.JarResource;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class NativeMethodCommitTransactionTest {
    private static final String LOADER = "protected/runtime/Loader77";
    private static final String NATIVE_ANNOTATION =
            "Ldev/skidfuscator/annotations/NativeObfuscation;";

    @Test
    void commitsResourcesAndInitializationBeforeRemovingDirectMethodCode() throws Exception {
        final Target target = ordinaryTarget("sample/DirectTarget", Opcodes.ACC_PUBLIC, "value", "()I");
        target.method().node.invisibleAnnotations = new ArrayList<>(List.of(new AnnotationNode(NATIVE_ANNOTATION)));
        final JarContents contents = contents(target.owner());
        final NativeMethodCommitTransaction.CommitResult result = new NativeMethodCommitTransaction().commit(
                contents,
                loader(),
                List.of(new NativeMethodCommitTransaction.Direct(target.method())),
                jar -> {
                    jar.getResourceContents().add(new JarResource("native.bin", new byte[]{1, 2, 3}));
                    return List.of("native.bin");
                });

        assertEquals(1, result.methodCount());
        assertEquals(List.of("native.bin"), result.resources());
        assertTrue(target.method().isNative());
        assertEquals(0, target.method().node.instructions.size());
        assertTrue(target.method().node.invisibleAnnotations == null
                || target.method().node.invisibleAnnotations.stream()
                .noneMatch(annotation -> NATIVE_ANNOTATION.equals(annotation.desc)));
        assertEquals(2, contents.getClassContents().size());
        final MethodNode initializer = target.owner().getMethods().stream()
                .filter(MethodNode::isClinit).findFirst().orElseThrow();
        final org.objectweb.asm.tree.LdcInsnNode ownerLiteral = assertInstanceOf(
                org.objectweb.asm.tree.LdcInsnNode.class, initializer.node.instructions.getFirst());
        assertEquals(org.objectweb.asm.Type.getObjectType(target.owner().getName()), ownerLiteral.cst);
        final MethodInsnNode load = assertInstanceOf(MethodInsnNode.class, ownerLiteral.getNext());
        assertEquals(LOADER, load.owner);
        assertEquals("ensureBound", load.name);
        assertEquals("(Ljava/lang/Class;)V", load.desc);
        assertTrue(initializer.node.maxStack >= 1);
        assertTrue(ClassHelper.toByteArray(target.owner(), ClassWriter.COMPUTE_MAXS).length > 0);
    }

    @Test
    void restoresStagedResourcesInitializerAnnotationsAndCodeAfterLateFailure() throws Exception {
        final Target target = ordinaryTarget("sample/RollbackTarget", Opcodes.ACC_PUBLIC, "value", "()I");
        target.method().node.invisibleAnnotations = new ArrayList<>(List.of(new AnnotationNode(NATIVE_ANNOTATION)));
        final JarContents contents = contents(target.owner());
        target.method().node.attrs = new ArrayList<>(List.of(new ExplodingCodeAttribute()));
        contents.getResourceContents().add(new JarResource("sentinel.bin", new byte[]{9}));
        final int access = target.method().node.access;
        final int instructions = target.method().node.instructions.size();

        assertThrows(IllegalStateException.class, () -> new NativeMethodCommitTransaction().commit(
                contents,
                loader(),
                List.of(new NativeMethodCommitTransaction.Direct(target.method())),
                jar -> {
                    jar.getResourceContents().add(new JarResource("staged.bin", new byte[]{1}));
                    return List.of("staged.bin");
                }));

        assertEquals(access, target.method().node.access);
        assertEquals(instructions, target.method().node.instructions.size());
        assertFalse(target.method().isNative());
        assertTrue(target.method().node.invisibleAnnotations.stream()
                .anyMatch(annotation -> NATIVE_ANNOTATION.equals(annotation.desc)));
        assertFalse(target.owner().getMethods().stream().anyMatch(MethodNode::isClinit));
        assertEquals(1, contents.getClassContents().size());
        assertEquals(List.of("sentinel.bin"), contents.getResourceContents().stream()
                .map(JarResource::getName).toList());
    }

    @Test
    void installsPreparedClassInitializerWrapperAndSyntheticNativeHelper() throws Exception {
        final Target target = ordinaryTarget(
                "sample/InitializerTarget", Opcodes.ACC_STATIC, "<clinit>", "()V");
        final org.objectweb.asm.tree.MethodNode wrapper = new org.objectweb.asm.tree.MethodNode(
                Opcodes.ASM9, Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
        wrapper.instructions.add(new MethodInsnNode(
                Opcodes.INVOKESTATIC, target.owner().getName(), "skid$native$init", "()V", false));
        wrapper.instructions.add(new InsnNode(Opcodes.RETURN));
        wrapper.maxStack = 0;
        wrapper.maxLocals = 0;
        final org.objectweb.asm.tree.MethodNode helper = nativeHelper("skid$native$init", "()V");
        final JarContents contents = contents(target.owner());

        new NativeMethodCommitTransaction().commit(
                contents,
                loader(),
                List.of(new NativeMethodCommitTransaction.Wrapper(
                        target.method(), target.owner(), helper, wrapper)),
                jar -> List.of());

        assertFalse(target.method().isNative());
        final org.objectweb.asm.tree.LdcInsnNode ownerLiteral = assertInstanceOf(
                org.objectweb.asm.tree.LdcInsnNode.class, target.method().node.instructions.getFirst());
        assertEquals(org.objectweb.asm.Type.getObjectType(target.owner().getName()), ownerLiteral.cst);
        final MethodInsnNode load = assertInstanceOf(MethodInsnNode.class, ownerLiteral.getNext());
        assertEquals(LOADER, load.owner);
        assertEquals("ensureBound", load.name);
        assertEquals("(Ljava/lang/Class;)V", load.desc);
        assertTrue(target.method().node.maxStack >= 1);
        final MethodNode installedHelper = target.owner().getMethods().stream()
                .filter(method -> method.getName().equals("skid$native$init"))
                .findFirst().orElseThrow();
        assertTrue(installedHelper.isNative());
        assertTrue(installedHelper.isSynthetic());
        assertEquals(0, installedHelper.node.instructions.size());
        assertTrue(ClassHelper.toByteArray(target.owner(), ClassWriter.COMPUTE_MAXS).length > 0);
    }

    @Test
    void supportsInterfaceWrapperWithNativeHelperInConcreteCompanion() throws Exception {
        final Target interfaceTarget = interfaceTarget();
        interfaceTarget.method().node.invisibleAnnotations = new ArrayList<>(
                List.of(new AnnotationNode(NATIVE_ANNOTATION)));
        final ClassNode companion = ClassHelper.create(baseClass("sample/NativeCompanion", Opcodes.ACC_PUBLIC));
        final JarContents contents = contents(interfaceTarget.owner(), companion);
        final org.objectweb.asm.tree.MethodNode wrapper = new org.objectweb.asm.tree.MethodNode(
                Opcodes.ASM9, Opcodes.ACC_PUBLIC, "run", "()I", null, null);
        wrapper.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
        wrapper.instructions.add(new MethodInsnNode(
                Opcodes.INVOKESTATIC, companion.getName(), "skid$run", "(Lsample/ProtectedInterface;)I", false));
        wrapper.instructions.add(new InsnNode(Opcodes.IRETURN));
        wrapper.maxStack = 1;
        wrapper.maxLocals = 1;

        new NativeMethodCommitTransaction().commit(
                contents,
                loader(),
                List.of(new NativeMethodCommitTransaction.Wrapper(
                        interfaceTarget.method(), companion,
                        nativeHelper("skid$run", "(Lsample/ProtectedInterface;)I"), wrapper)),
                jar -> List.of());

        assertFalse(interfaceTarget.method().isNative());
        assertTrue(interfaceTarget.method().node.invisibleAnnotations == null
                || interfaceTarget.method().node.invisibleAnnotations.stream()
                .noneMatch(annotation -> NATIVE_ANNOTATION.equals(annotation.desc)));
        assertTrue(companion.getMethods().stream().anyMatch(method -> method.getName().equals("skid$run")
                && method.isNative()));
        assertTrue(ClassHelper.toByteArray(interfaceTarget.owner(), ClassWriter.COMPUTE_MAXS).length > 0);
        assertTrue(ClassHelper.toByteArray(companion, ClassWriter.COMPUTE_MAXS).length > 0);
    }

    @Test
    void stagingFailureDoesNotAddLoaderOrTouchMethods() throws Exception {
        final Target target = ordinaryTarget("sample/StagingTarget", Opcodes.ACC_PUBLIC, "value", "()I");
        final JarContents contents = contents(target.owner());
        assertThrows(IOException.class, () -> new NativeMethodCommitTransaction().commit(
                contents,
                loader(),
                List.of(new NativeMethodCommitTransaction.Direct(target.method())),
                jar -> {
                    jar.getResourceContents().add(new JarResource("partial.bin", new byte[]{1}));
                    throw new IOException("staging failed");
                }));
        assertFalse(target.method().isNative());
        assertFalse(target.owner().getMethods().stream().anyMatch(MethodNode::isClinit));
        assertEquals(1, contents.getClassContents().size());
        assertEquals(0, contents.getResourceContents().size());
    }

    @Test
    void installsJavaLinkageHelpersInsideTheSameAtomicTransaction() throws Exception {
        final Target target = ordinaryTarget("sample/LinkageTarget", Opcodes.ACC_PUBLIC, "value", "()I");
        final JarContents contents = contents(target.owner());
        final org.objectweb.asm.tree.MethodNode helper = new org.objectweb.asm.tree.MethodNode(
                Opcodes.ASM9, Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                "skid$link$0", "()I", null, null);
        helper.instructions.add(new InsnNode(Opcodes.ICONST_2));
        helper.instructions.add(new InsnNode(Opcodes.IRETURN));
        helper.maxStack = 1;

        new NativeMethodCommitTransaction().commit(
                contents, loader(),
                List.of(new NativeMethodCommitTransaction.Direct(target.method())),
                List.of(new JavaLinkageHelper(target.owner(), helper, "invokedynamic")),
                jar -> List.of());

        assertTrue(target.owner().getMethods().stream().anyMatch(method ->
                method.getName().equals("skid$link$0") && method.isStatic() && method.isSynthetic()
                        && !method.isNative()));
        assertTrue(ClassHelper.toByteArray(target.owner(), ClassWriter.COMPUTE_MAXS).length > 0);
    }

    @Test
    void restoresAnExistingInitializerAfterLateMutationFailure() throws Exception {
        final Target target = ordinaryTarget("sample/ExistingInitializer", Opcodes.ACC_PUBLIC, "value", "()I");
        final org.objectweb.asm.tree.MethodNode asm = new org.objectweb.asm.tree.MethodNode(
                Opcodes.ASM9, Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
        asm.instructions.add(new InsnNode(Opcodes.NOP));
        asm.instructions.add(new InsnNode(Opcodes.RETURN));
        final MethodNode initializer = new MethodNode(asm, target.owner());
        target.owner().addMethod(initializer);
        final JarContents contents = contents(target.owner());
        target.method().node.attrs = new ArrayList<>(List.of(new ExplodingCodeAttribute()));
        assertThrows(IllegalStateException.class, () -> new NativeMethodCommitTransaction().commit(
                contents, loader(), List.of(new NativeMethodCommitTransaction.Direct(target.method())),
                jar -> List.of()));
        assertEquals(2, initializer.node.instructions.size());
        assertEquals(Opcodes.NOP, initializer.node.instructions.getFirst().getOpcode());
        assertEquals(Opcodes.RETURN, initializer.node.instructions.getLast().getOpcode());
        assertTrue(target.owner().node.methods.contains(initializer.node));
        assertFalse(target.method().isNative());
        assertEquals(1, contents.getClassContents().size());
    }

    @Test
    void copiesKeepTheirBodyAndRemovedEntriesLeaveNoBindingInitializer() throws Exception {
        Target copy = ordinaryTarget("sample/Copy", Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "value", "()I");
        Target removed = ordinaryTarget("sample/Removed", Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC, "value", "()I");
        var originalCode = copy.method().node.instructions;
        new NativeMethodCommitTransaction().commit(contents(copy.owner(), removed.owner()), loader(),
                List.of(new NativeMethodCommitTransaction.JavaCopy(copy.method()),
                        new NativeMethodCommitTransaction.Remove(removed.method())), jar -> List.of());
        org.junit.jupiter.api.Assertions.assertSame(originalCode, copy.method().node.instructions);
        assertFalse(copy.method().isNative());
        assertFalse(removed.owner().getMethods().contains(removed.method()));
        assertFalse(removed.owner().node.methods.contains(removed.method().node));
        assertFalse(copy.owner().getMethods().stream().anyMatch(MethodNode::isClinit));
        assertFalse(removed.owner().getMethods().stream().anyMatch(MethodNode::isClinit));
    }

    @Test
    void restoresRemovedDeclarationIfLaterMutationFails() throws Exception {
        Target removed = ordinaryTarget("sample/Removed", Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC, "value", "()I");
        Target failure = ordinaryTarget("sample/Failure", Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "value", "()I");
        var contents = contents(removed.owner(), failure.owner());
        failure.method().node.attrs = new ArrayList<>(List.of(new ExplodingCodeAttribute()));
        assertThrows(IllegalStateException.class, () -> new NativeMethodCommitTransaction().commit(contents, loader(),
                List.of(new NativeMethodCommitTransaction.Remove(removed.method()),
                        new NativeMethodCommitTransaction.Direct(failure.method())), jar -> List.of()));
        assertTrue(removed.owner().getMethods().contains(removed.method()));
        assertTrue(removed.owner().node.methods.contains(removed.method().node));
        assertEquals(2, removed.method().node.instructions.size());
    }

    private static NativeLoaderGenerator.GeneratedLoader loader() {
        final NativeLoaderSpec.Library library = new NativeLoaderSpec.Library(
                NativeTarget.WINDOWS_X86_64,
                "META-INF/skidfuscator/native/commit-test/windows-x86_64/protected.dll",
                "a".repeat(64),
                "protected.dll",
                1);
        return new NativeLoaderGenerator().generate(new NativeLoaderSpec(
                LOADER,
                "commit-test",
                NativeCompilationInstaller.manifestResourcePath("commit-test"),
                "b".repeat(64),
                1,
                Map.of(NativeTarget.WINDOWS_X86_64, library)));
    }

    private static org.objectweb.asm.tree.MethodNode nativeHelper(final String name, final String desc) {
        return new org.objectweb.asm.tree.MethodNode(
                Opcodes.ASM9,
                Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC | Opcodes.ACC_NATIVE,
                name,
                desc,
                null,
                null);
    }

    private static Target ordinaryTarget(
            final String ownerName,
            final int access,
            final String name,
            final String desc
    ) {
        final org.objectweb.asm.tree.ClassNode asmOwner = baseClass(ownerName, Opcodes.ACC_PUBLIC);
        final org.objectweb.asm.tree.MethodNode asmMethod = new org.objectweb.asm.tree.MethodNode(
                Opcodes.ASM9, access, name, desc, null, null);
        if ("<clinit>".equals(name)) {
            asmMethod.instructions.add(new InsnNode(Opcodes.RETURN));
            asmMethod.maxLocals = 0;
        } else {
            asmMethod.instructions.add(new InsnNode(Opcodes.ICONST_1));
            asmMethod.instructions.add(new InsnNode(Opcodes.IRETURN));
            asmMethod.maxLocals = (access & Opcodes.ACC_STATIC) == 0 ? 1 : 0;
        }
        asmMethod.maxStack = 1;
        asmOwner.methods.add(asmMethod);
        final ClassNode owner = ClassHelper.create(asmOwner);
        return new Target(owner, owner.getMethods().get(0));
    }

    private static Target interfaceTarget() {
        final org.objectweb.asm.tree.ClassNode asmOwner = baseClass(
                "sample/ProtectedInterface",
                Opcodes.ACC_PUBLIC | Opcodes.ACC_INTERFACE | Opcodes.ACC_ABSTRACT);
        final org.objectweb.asm.tree.MethodNode method = new org.objectweb.asm.tree.MethodNode(
                Opcodes.ASM9, Opcodes.ACC_PUBLIC, "run", "()I", null, null);
        method.instructions.add(new InsnNode(Opcodes.ICONST_1));
        method.instructions.add(new InsnNode(Opcodes.IRETURN));
        method.maxStack = 1;
        method.maxLocals = 1;
        asmOwner.methods.add(method);
        final ClassNode owner = ClassHelper.create(asmOwner);
        return new Target(owner, owner.getMethods().get(0));
    }

    private static org.objectweb.asm.tree.ClassNode baseClass(final String name, final int access) {
        final org.objectweb.asm.tree.ClassNode owner = new org.objectweb.asm.tree.ClassNode();
        owner.visit(Opcodes.V1_8,
                access | ((access & Opcodes.ACC_INTERFACE) == 0 ? Opcodes.ACC_SUPER : 0),
                name, null, "java/lang/Object", null);
        return owner;
    }

    private static JarContents contents(final ClassNode... owners) {
        final JarContents contents = new JarContents();
        for (final ClassNode owner : owners) {
            contents.getClassContents().add(new JarClassData(
                    owner.getName() + ".class",
                    ClassHelper.toByteArray(owner, ClassWriter.COMPUTE_MAXS),
                    owner));
        }
        return contents;
    }

    private record Target(ClassNode owner, MethodNode method) {
    }

    private static final class ExplodingCodeAttribute extends Attribute {
        private ExplodingCodeAttribute() {
            super("ExplodingCode");
        }

        @Override
        public boolean isCodeAttribute() {
            throw new IllegalStateException("late commit failure");
        }
    }
}
