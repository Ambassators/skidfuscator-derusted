package dev.skidfuscator.obfuscator.nativebackend.key;

import dev.skidfuscator.config.nativeobfuscation.NativeConfig;
import dev.skidfuscator.nativeir.NativeBackend;
import dev.skidfuscator.nativeir.NativeFunction;
import dev.skidfuscator.obfuscator.Skidfuscator;
import org.mapleir.asm.ClassNode;
import org.mapleir.asm.MethodNode;
import org.mapleir.ir.code.Expr;
import org.mapleir.ir.code.expr.invoke.StaticInvocationExpr;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.InsnNode;
import org.topdank.byteengineer.commons.data.JarClassData;
import org.topdank.byteengineer.commons.data.JarContents;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Per-build collection of native seed helpers. Application methods only receive
 * primitive calls; helper bodies are constructed directly in native IR. The
 * generated companion is attached by NativePipeline's commit boundary, never
 * through ordinary application-method selection or the Java transformer passes.
 */
public final class NativeThreadedKeyRegistry {
    private static final int MAX_HELPERS = 60_000;
    private final Skidfuscator skidfuscator;
    private final SecureRandom random = new SecureRandom();
    private final Map<MethodNode, Map<Mapping, Prepared>> bySite = new IdentityHashMap<>();
    private final List<Prepared> helpers = new ArrayList<>();
    private ClassNode owner;
    private String identifier;
    private boolean sealed;

    public NativeThreadedKeyRegistry(final Skidfuscator skidfuscator) {
        this.skidfuscator = Objects.requireNonNull(skidfuscator, "skidfuscator");
    }

    public synchronized Expr reconstruct(
            final MethodNode site,
            final boolean wide,
            final long outcome,
            final long starting,
            final Expr runtimeSeed
    ) {
        Objects.requireNonNull(site, "site");
        Objects.requireNonNull(runtimeSeed, "runtimeSeed");
        final NativeConfig config = skidfuscator.getConfig().getNativeConfig();
        config.getThreadedKeyConfig().validate(config.isEnabled());
        if (!config.getThreadedKeyConfig().isEnabled()) {
            throw new IllegalStateException("Native threaded-key protection is not enabled");
        }
        if (!runtimeSeed.getType().equals(wide ? Type.LONG_TYPE : Type.INT_TYPE)) {
            throw new IllegalArgumentException("Threaded-key argument width does not match its native descriptor");
        }
        final Mapping mapping = new Mapping(wide, wide ? starting : (int) starting,
                wide ? outcome : (int) outcome);
        final Map<Mapping, Prepared> siteHelpers = bySite.computeIfAbsent(site, ignored -> new HashMap<>());
        Prepared helper = siteHelpers.get(mapping);
        if (helper == null) {
            if (sealed) {
                throw new IllegalStateException("A new threaded-key helper was requested after native compilation");
            }
            if (helpers.size() >= MAX_HELPERS) {
                throw new IllegalStateException("Native threaded-key helper count exceeds the class-file limit");
            }
            ensureOwner();
            final String name = "k" + helpers.size();
            final String descriptor = wide ? "(J)J" : "(I)I";
            final org.objectweb.asm.tree.MethodNode placeholder = new org.objectweb.asm.tree.MethodNode(
                    Opcodes.ASM9, Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                    name, descriptor, null, null);
            // A code-bearing, fail-closed placeholder is required by the direct commit
            // transaction. It contains no seed material and is never a Java fallback.
            placeholder.instructions.add(new InsnNode(Opcodes.ACONST_NULL));
            placeholder.instructions.add(new InsnNode(Opcodes.ATHROW));
            placeholder.maxStack = 1;
            placeholder.maxLocals = wide ? 2 : 1;
            final MethodNode method = new MethodNode(placeholder, owner);
            owner.addMethod(method);
            final NativeFunction function = NativeThreadedKeyFunction.create(
                    "skid_key_" + identifier + "_" + helpers.size(), owner.getName(), name,
                    NativeBackend.valueOf(config.getThreadedKeyConfig().getMode().name()),
                    wide, mapping.starting(), mapping.outcome(), random);
            helper = new Prepared(method, function);
            helpers.add(helper);
            siteHelpers.put(mapping, helper);
            skidfuscator.reserveNativeGeneratedMethod(owner.getName(), name, descriptor);
            skidfuscator.reserveNativeReferencedMember(owner.getName(), name, descriptor);
        }
        return new StaticInvocationExpr(new Expr[]{runtimeSeed}, helper.method().owner.getName(),
                helper.method().getName(), helper.method().getDesc());
    }

    public synchronized boolean isEmpty() {
        return helpers.isEmpty();
    }

    public synchronized int size() {
        return helpers.size();
    }

    /** Freeze the helper set before generating the compiler manifest and registration table. */
    public synchronized List<Prepared> seal() {
        sealed = true;
        return List.copyOf(helpers);
    }

    /** The returned class must be staged and removed on commit failure with other companions. */
    public synchronized List<JarClassData> generatedCompanions() {
        if (!sealed) {
            throw new IllegalStateException("Threaded-key helpers must be sealed before staging");
        }
        if (owner == null) {
            return List.of();
        }
        final ClassWriter writer = new ClassWriter(0);
        owner.node.accept(writer);
        return List.of(new JarClassData(owner.getName() + ".class", writer.toByteArray(), owner));
    }

    private void ensureOwner() {
        if (owner != null) return;
        final JarContents contents = skidfuscator.getJarContents();
        for (int attempt = 0; attempt < 16; attempt++) {
            final byte[] bytes = new byte[12];
            random.nextBytes(bytes);
            identifier = HexFormat.of().formatHex(bytes);
            final String name = "skid/native/Key_" + identifier;
            if (contents != null && (contents.getClassContents().stream().anyMatch(data ->
                    name.equals(data.getClassNode().getName()) || (name + ".class").equals(data.getName()))
                    || contents.getResourceContents().stream().anyMatch(resource ->
                    (name + ".class").equals(resource.getName())))) {
                continue;
            }
            final org.objectweb.asm.tree.ClassNode node = new org.objectweb.asm.tree.ClassNode(Opcodes.ASM9);
            node.version = Opcodes.V1_8;
            node.access = Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL | Opcodes.ACC_SUPER | Opcodes.ACC_SYNTHETIC;
            node.name = name;
            node.superName = "java/lang/Object";
            final ClassWriter classWriter = new ClassWriter(0);
            node.accept(classWriter);
            owner = org.mapleir.asm.ClassHelper.create(classWriter.toByteArray());
            skidfuscator.reserveNativeGeneratedClass(name);
            return;
        }
        throw new IllegalStateException("Unable to allocate a collision-free native key companion");
    }

    public record Prepared(MethodNode method, NativeFunction function) {
        public Prepared {
            Objects.requireNonNull(method, "method");
            Objects.requireNonNull(function, "function");
        }
    }

    private record Mapping(boolean wide, long starting, long outcome) {
    }
}
