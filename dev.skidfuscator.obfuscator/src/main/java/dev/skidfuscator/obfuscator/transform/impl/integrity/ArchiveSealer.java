package dev.skidfuscator.obfuscator.transform.impl.integrity;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodNode;
import sdk.integrity.ArchiveIntegrity;
import sdk.integrity.JvmPolicy;
import sdk.integrity.RuntimeGuard;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.Locale;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;

/**
 * Java-8-compatible final-archive sealing tool. Also compiled standalone by legacy Forge builds.
 * This is a local integrity root, NOT a publisher signature or remote attestation mechanism.
 */
public final class ArchiveSealer {
    private static final String OWNER = "sdk/integrity/ReleaseSeal";
    private static final String[] REQUIRED = {
            "sdk/integrity/ArchiveIntegrity.class", "sdk/integrity/JvmPolicy.class",
            "sdk/integrity/RuntimeGuard.class", "sdk/integrity/RuntimeGuard$1.class",
            "sdk/integrity/RuntimeGuard$State.class", ArchiveIntegrity.SEAL
    };

    private ArchiveSealer() { }

    public static void main(String[] args) throws Exception {
        if (args.length == 2 && "verify".equals(args[0])) {
            System.out.println("[integrity] verified " + verify(new File(args[1])) + " archive entries");
        } else if (args.length >= 3 && args.length <= 5 && "seal".equals(args[0])) {
            int policy = args.length > 3 ? Integer.parseInt(args[3]) : JvmPolicy.STRICT;
            long interval = args.length > 4 ? Long.parseLong(args[4]) : 30000L;
            seal(new File(args[1]), new File(args[2]), policy, interval);
            System.out.println("[integrity] sealed release; policy=" + policy + ", intervalMs=" + interval);
        } else if (args.length == 3 && "development".equals(args[0])) {
            development(new File(args[1]), new File(args[2]));
            System.out.println("[integrity] development artifact: NOT release-protected");
        } else {
            throw new IllegalArgumentException("Usage: seal INPUT OUTPUT [POLICY=127] [INTERVAL_MS=30000]"
                    + " | verify JAR | development INPUT OUTPUT");
        }
    }

    public static void seal(File input, File output, int policy, long interval) throws IOException {
        JvmPolicy.validate(policy);
        RuntimeGuard.validateInterval(interval);
        requireRuntime(input);
        byte[] index = ArchiveIntegrity.createIndex(input);
        String hash = ArchiveIntegrity.hex(ArchiveIntegrity.digest(index));
        rewrite(input, output, index, sealClass(hash, policy, interval, false), true);
    }

    /** Explicit build-time development marker; production verification always rejects it. */
    public static void development(File input, File output) throws IOException {
        requireRuntime(input);
        ArchiveIntegrity.createIndex(input); // validate names, duplicates, and size bounds first
        rewrite(input, output, null, sealClass("", 0, 30000L, true), false);
    }

    /** Reads and validates metadata as bytecode data, never by executing a class from the input. */
    public static int verify(File archive) throws IOException {
        requireRuntime(archive);
        byte[] root;
        try (JarFile jar = new JarFile(archive, true);
             InputStream in = jar.getInputStream(jar.getJarEntry(ArchiveIntegrity.SEAL))) {
            root = ArchiveIntegrity.readBounded(in, 65536);
        }
        try {
            ClassNode node = new ClassNode();
            new ClassReader(root).accept(node, 0);
            String hash = (String) constant(node, "indexHash", "()Ljava/lang/String;");
            int policy = ((Integer) constant(node, "policy", "()I")).intValue();
            long interval = ((Long) constant(node, "intervalMillis", "()J")).longValue();
            int dev = ((Integer) constant(node, "development", "()Z")).intValue();
            JvmPolicy.validate(policy);
            RuntimeGuard.validateInterval(interval);
            if (dev != 0 || !Arrays.equals(root, sealClass(hash, policy, interval, false))) {
                throw new IOException("[integrity] Non-canonical or development release seal");
            }
            return ArchiveIntegrity.verify(archive, hash);
        } catch (RuntimeException e) {
            throw new IOException("[integrity] Malformed release seal", e);
        }
    }

    private static Object constant(ClassNode node, String name, String descriptor) throws IOException {
        for (Object value : node.methods) {
            MethodNode method = (MethodNode) value;
            if (name.equals(method.name) && descriptor.equals(method.desc)) {
                AbstractInsnNode first = method.instructions.getFirst();
                if (!(first instanceof LdcInsnNode)) throw new IOException("[integrity] Invalid seal constant");
                return ((LdcInsnNode) first).cst;
            }
        }
        throw new IOException("[integrity] Missing seal method " + name);
    }

    private static byte[] sealClass(String hash, int policy, long interval, boolean development) {
        ClassWriter writer = new ClassWriter(0);
        writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL | Opcodes.ACC_SUPER,
                OWNER, null, "java/lang/Object", null);
        MethodVisitor constructor = writer.visitMethod(Opcodes.ACC_PRIVATE, "<init>", "()V", null, null);
        constructor.visitCode();
        constructor.visitVarInsn(Opcodes.ALOAD, 0);
        constructor.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        constructor.visitInsn(Opcodes.RETURN);
        constructor.visitMaxs(1, 1);
        constructor.visitEnd();
        constantMethod(writer, "development", "()Z", Integer.valueOf(development ? 1 : 0), Opcodes.IRETURN, 1);
        constantMethod(writer, "indexHash", "()Ljava/lang/String;", hash, Opcodes.ARETURN, 1);
        constantMethod(writer, "policy", "()I", Integer.valueOf(policy), Opcodes.IRETURN, 1);
        constantMethod(writer, "intervalMillis", "()J", Long.valueOf(interval), Opcodes.LRETURN, 2);
        writer.visitEnd();
        return writer.toByteArray();
    }

    private static void constantMethod(ClassWriter writer, String name, String desc,
                                       Object value, int returnOpcode, int stack) {
        MethodVisitor method = writer.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, name, desc, null, null);
        method.visitCode();
        method.visitLdcInsn(value);
        method.visitInsn(returnOpcode);
        method.visitMaxs(stack, 0);
        method.visitEnd();
    }

    private static void requireRuntime(File input) throws IOException {
        try (JarFile jar = new JarFile(input, true)) {
            for (String path : REQUIRED) {
                JarEntry entry = jar.getJarEntry(path);
                if (entry == null || entry.isDirectory()) {
                    throw new IOException("[integrity] Required runtime class absent: " + path);
                }
            }
            Enumeration<JarEntry> entries = jar.entries();
            while (entries.hasMoreElements()) {
                String name = entries.nextElement().getName().toUpperCase(Locale.ROOT);
                if (name.startsWith("META-INF/") && name.indexOf('/', 9) < 0
                        && (name.endsWith(".SF") || name.endsWith(".RSA") || name.endsWith(".DSA") || name.endsWith(".EC"))) {
                    throw new IOException("[integrity] Embedded JAR signatures are unsupported; use detached final-archive signing");
                }
            }
        }
    }

    private static void rewrite(File input, File output, byte[] index, byte[] root, boolean release) throws IOException {
        Path destination = output.toPath().toAbsolutePath();
        Files.createDirectories(destination.getParent());
        Path stage = Files.createTempFile(destination.getParent(), ".integrity-", ".jar");
        try {
            try (JarFile source = new JarFile(input, true);
                 JarOutputStream target = new JarOutputStream(Files.newOutputStream(stage))) {
                Enumeration<JarEntry> entries = source.entries();
                while (entries.hasMoreElements()) {
                    JarEntry entry = entries.nextElement();
                    if (ArchiveIntegrity.reserved(entry.getName())) continue;
                    JarEntry copy = new JarEntry(entry.getName());
                    copy.setTime(Math.max(0L, entry.getTime()));
                    target.putNextEntry(copy);
                    if (!entry.isDirectory()) {
                        try (InputStream in = source.getInputStream(entry)) {
                            byte[] buffer = new byte[32768];
                            long length = 0;
                            int count;
                            while ((count = in.read(buffer)) != -1) {
                                length += count;
                                if (length > ArchiveIntegrity.MAX_ENTRY_BYTES) throw new IOException("[integrity] Entry grew during sealing");
                                target.write(buffer, 0, count);
                            }
                        }
                    }
                    target.closeEntry();
                }
                put(target, ArchiveIntegrity.SEAL, root);
                if (index != null) put(target, ArchiveIntegrity.INDEX, index);
            }
            if (release) verify(stage.toFile());
            else ArchiveIntegrity.createIndex(stage.toFile());
            try {
                Files.move(stage, destination, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(stage, destination, StandardCopyOption.REPLACE_EXISTING);
            }
        } finally {
            Files.deleteIfExists(stage);
        }
    }

    private static void put(JarOutputStream out, String name, byte[] data) throws IOException {
        JarEntry entry = new JarEntry(name);
        entry.setTime(0L);
        out.putNextEntry(entry);
        out.write(data);
        out.closeEntry();
    }
}
