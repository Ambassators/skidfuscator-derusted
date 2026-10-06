package dev.skidfuscator.obfuscator.transform.impl.integrity;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

/** Straight-line, stack-balanced checkpoints; existing StackMapTable frames are preserved. */
public final class RuntimeProtectionInstrumenter {
    private static final String GUARD = "sdk/integrity/RuntimeGuard";

    private RuntimeProtectionInstrumenter() { }

    public static byte[] instrument(byte[] bytes, boolean methodChecks) {
        ClassNode node = new ClassNode();
        new ClassReader(bytes).accept(node, 0);
        if (node.name.startsWith("sdk/") || (node.access & (Opcodes.ACC_INTERFACE | Opcodes.ACC_ANNOTATION)) != 0
                || "module-info".equals(node.name)) return bytes;
        MethodNode clinit = null;
        for (Object value : node.methods) {
            MethodNode method = (MethodNode) value;
            if ("<clinit>".equals(method.name)) clinit = method;
            else if (methodChecks && !"<init>".equals(method.name)
                    && (method.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) == 0
                    && !contains(method, "assertHealthy", "()V")) {
                method.instructions.insert(new MethodInsnNode(Opcodes.INVOKESTATIC, GUARD,
                        "assertHealthy", "()V", false));
            }
        }
        if (clinit == null) {
            clinit = new MethodNode(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
            clinit.instructions.add(new InsnNode(Opcodes.RETURN));
            node.methods.add(clinit);
        }
        if (!contains(clinit, "bootstrap", "(Ljava/lang/Class;)Z")) {
            InsnList start = new InsnList();
            start.add(new LdcInsnNode(Type.getObjectType(node.name)));
            start.add(new MethodInsnNode(Opcodes.INVOKESTATIC, GUARD, "bootstrap", "(Ljava/lang/Class;)Z", false));
            start.add(new InsnNode(Opcodes.POP));
            clinit.instructions.insert(start);
        }
        ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        node.accept(writer);
        return writer.toByteArray();
    }

    private static boolean contains(MethodNode method, String name, String descriptor) {
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn instanceof MethodInsnNode) {
                MethodInsnNode call = (MethodInsnNode) insn;
                if (GUARD.equals(call.owner) && name.equals(call.name) && descriptor.equals(call.desc)) return true;
            }
        }
        return false;
    }
}
