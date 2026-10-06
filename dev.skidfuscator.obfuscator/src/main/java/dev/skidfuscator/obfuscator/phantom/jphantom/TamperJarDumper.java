package dev.skidfuscator.obfuscator.phantom.jphantom;

import dev.skidfuscator.obfuscator.Skidfuscator;
import dev.skidfuscator.obfuscator.transform.impl.integrity.RuntimeProtection;
import dev.skidfuscator.obfuscator.creator.SkidFlowGraphDumper;
import dev.skidfuscator.obfuscator.transform.impl.integrity.IntegrityGraph;
import org.mapleir.app.service.ApplicationClassSource;
import org.mapleir.app.service.ClassTree;
import org.mapleir.asm.ClassNode;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.commons.ClassRemapper;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.topdank.byteengineer.commons.data.JarClassData;
import org.topdank.byteengineer.commons.data.JarContents;
import org.topdank.byteengineer.commons.data.JarResource;

import sdk.LongHashFunction;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;

/**
 * Two-pass jar dumper that materialises the tamper-protection mesh
 * (cross-class self-integrity checks) into the output.
 *
 * <p>Whole-file (Tier A) hashing means a holder A can only be stamped once every
 * class it verifies has its final bytes frozen, so a single streaming pass is
 * impossible. This dumper therefore:</p>
 * <ol>
 *   <li><b>Pass 1</b> — serialise every class to its final remapped bytes and
 *       buffer them (mirroring the normal dump: exempt handling,
 *       {@code COMPUTE_FRAMES}/{@code COMPUTE_MAXS}, the
 *       strict serialization failure handling and ordinary JAR entry naming).</li>
 *   <li><b>Stamp</b> — build a DAG mesh over eligible classes and, in
 *       reverse-topological order, prepend
 *       {@code Tamper.verify(B.class, hash(B))} to each holder's {@code <clinit>}
 *       using the real checksum of B's frozen bytes.</li>
 *   <li><b>Pass 2</b> — write every class (stamped where applicable) and the
 *       resource entries.</li>
 * </ol>
 *
 * <p>This path is only used when {@code tamperProtection.enabled} (and
 * {@code sdk.enabled}); otherwise the legacy single-pass dumper runs unchanged.</p>
 */
public class TamperJarDumper extends PhantomResolvingJarDumper {

    private final Skidfuscator skidfuscator;
    private final JarContents contents;
    private final ApplicationClassSource source;

    public TamperJarDumper(final Skidfuscator skidfuscator,
                           final JarContents contents,
                           final ApplicationClassSource source) {
        super(skidfuscator, contents, source);
        this.skidfuscator = skidfuscator;
        this.contents = contents;
        this.source = source;
    }

    private static final class Buffered {
        final String entryName;     // jar entry path (with fileCrasher slash if enabled)
        final byte[] bytes;         // remapped serialized bytes (pre-stamp)
        final String finalInternal; // final internal name (a/b/C); null if exempt
        final boolean eligible;     // may host / be a tamper check

        Buffered(final String entryName, final byte[] bytes,
                 final String finalInternal, final boolean eligible) {
            this.entryName = entryName;
            this.bytes = bytes;
            this.finalInternal = finalInternal;
            this.eligible = eligible;
        }
    }

    @Override
    public void dump(final File file) throws IOException {
        if (file.exists()) {
            file.delete();
        }
        file.createNewFile();

        // fileCrasher is bypassed by the MapleJarUtil gate before reaching here; the
        // trailing-slash naming below is kept only as defensive parity.
        final boolean fileCrasher = skidfuscator.getConfig().getBoolean("fileCrasher.enabled", false);
        final String action = skidfuscator.getConfig().getString("tamperProtection.action", "THROW");
        final String verifyMethod;
        if ("EXIT".equalsIgnoreCase(action)) {
            verifyMethod = "verifyExit";
        } else if ("SILENT".equalsIgnoreCase(action)) {
            verifyMethod = "verifySilent";
        } else {
            verifyMethod = "verify";
        }

        // ---- Pass 1: serialise every class to its final remapped bytes ----
        final ClassTree tree = source.getClassTree();
        final List<Buffered> ordered = new ArrayList<>();
        final Map<String, Buffered> byFinal = new LinkedHashMap<>();

        for (final JarClassData classData : new LinkedList<>(contents.getClassContents())) {
            final ClassNode cn = classData.getClassNode();
            for (final MethodNode method : cn.node.methods) {
                method.localVariables = null;
            }

            final boolean exempt = !cn.isVirtual() && skidfuscator.getExemptAnalysis().isExempt(cn);

            final String entryName;
            final byte[] bytes;
            String finalInternal = null;
            boolean eligible = false;

            if (exempt) {
                entryName = classData.getName() + (fileCrasher ? "/" : "");
                bytes = serialize(cn, tree, 0);
            } else {
                final String dotted = skidfuscator.getClassRemapper().mapOrDefault(
                        Type.getObjectType(classData.getName()
                                .replace(".class", "")
                                .replace(".", "/")).getInternalName()
                );
                finalInternal = dotted.replace(".", "/");
                entryName = finalInternal + ".class" + (fileCrasher ? "/" : "");

                final int flags = SkidFlowGraphDumper.TEST_COMPUTE
                        ? ClassWriter.COMPUTE_MAXS
                        : ClassWriter.COMPUTE_FRAMES;
                final byte[] serialized;
                try {
                    serialized = serialize(cn, tree, flags);
                } catch (final RuntimeException failure) {
                    throw new IOException("Unable to serialize protected class " + cn.getName()
                            + "; refusing unverified fallback bytecode", failure);
                }
                bytes = serialized;
                eligible = isEligible(cn, finalInternal);
            }

            final Buffered buffered = new Buffered(entryName, bytes, finalInternal, eligible);
            ordered.add(buffered);
            if (finalInternal != null) {
                byFinal.put(finalInternal, buffered);
            }
        }

        // ---- Build the Tier A mesh (DAG chain over eligible classes) ----
        final List<String> eligible = new ArrayList<>();
        for (final Buffered buffered : ordered) {
            if (buffered.eligible) {
                eligible.add(buffered.finalInternal);
            }
        }
        Collections.sort(eligible); // deterministic ordering => deterministic mesh

        final IntegrityGraph graph = new IntegrityGraph();
        for (final String node : eligible) {
            graph.addNode(node);
        }
        // c_i verifies c_{i-1}: edges only ever point to a lower index => acyclic.
        for (int i = 1; i < eligible.size(); i++) {
            graph.addEdge(eligible.get(i), eligible.get(i - 1));
        }

        final Map<String, byte[]> frozen = stamp(graph, byFinal, tree, verifyMethod);

        // ---- Pass 2: write every class (stamped where applicable) + resources ----
        final JarOutputStream jos = new JarOutputStream(new FileOutputStream(file));
        try {
            for (final Buffered buffered : ordered) {
                final byte[] out = (buffered.finalInternal != null
                        && frozen.containsKey(buffered.finalInternal))
                        ? frozen.get(buffered.finalInternal)
                        : buffered.bytes;
                jos.putNextEntry(new JarEntry(buffered.entryName));
                jos.write(out);
                jos.flush();
            }
            for (final JarResource res : new LinkedList<>(contents.getResourceContents())) {
                dumpResource(jos, res.getName(), res.getData());
            }
        } finally {
            jos.flush();
            jos.close();
        }
    }

    /**
     * Freeze every class's final bytes, injecting checks into holders in
     * reverse-topological order. Classes outside the mesh are absent from the
     * returned map (Pass 2 falls back to their buffered bytes).
     */
    private Map<String, byte[]> stamp(final IntegrityGraph graph,
                                      final Map<String, Buffered> byFinal,
                                      final ClassTree tree,
                                      final String verifyMethod) {
        final Map<String, byte[]> frozen = new HashMap<>();
        if (graph.nodes().size() < 2) {
            throw new IllegalStateException("Tamper mesh requires at least two eligible classes");
        }

        final List<String> order = graph.dependencyOrder();
        if (order == null) {
            throw new IllegalStateException("Tamper integrity graph must be acyclic");
        }

        for (final String name : order) {
            final Buffered holder = byFinal.get(name);
            final List<String> targets = graph.targetsOf(name);
            if (holder == null) {
                throw new IllegalStateException("Missing protected class " + name);
            }
            if (targets.isEmpty()) {
                frozen.put(name, holder.bytes);
                continue;
            }
            try {
                final org.objectweb.asm.tree.ClassNode node = read(holder.bytes);
                final MethodNode clinit = clinitOf(node);
                final InsnList prologue = new InsnList();
                for (final String target : targets) {
                    final byte[] targetBytes = frozen.get(target);
                    if (targetBytes == null) {
                        // Must never happen: dependency order freezes every target first.
                        throw new IllegalStateException(
                                "target " + target + " was not frozen before holder " + name);
                    }
                    final long hash = LongHashFunction.xx3().hashBytes(targetBytes);
                    prologue.add(new LdcInsnNode(Type.getObjectType(target)));
                    prologue.add(new LdcInsnNode(Long.valueOf(hash)));
                    prologue.add(new MethodInsnNode(
                            Opcodes.INVOKESTATIC, "sdk/Tamper", verifyMethod,
                            "(Ljava/lang/Class;J)V", false));
                }
                // Prepend at <clinit> entry. insert(InsnList) places the prologue at the
                // very start; it is stack-balanced (push Class + long, consumed by the
                // void call), so every downstream frame remains valid under COMPUTE_MAXS.
                clinit.instructions.insert(prologue);
                frozen.put(name, write(node, tree));
            } catch (final RuntimeException failure) {
                throw new IllegalStateException("Unable to stamp protected class " + name, failure);
            }
        }

        logCoverage(graph);
        return frozen;
    }

    private void logCoverage(final IntegrityGraph graph) {
        final Set<String> exposed = graph.exposedSources();
        final int checked = graph.checkedNodes().size();
        final String example = exposed.isEmpty() ? "" : " (e.g. " + exposed.iterator().next() + ")";
        Skidfuscator.LOGGER.post(
                "\r[tamper] meshed " + graph.nodes().size() + " classes; "
                        + checked + " verified by a sibling; "
                        + exposed.size() + " unverified source(s)" + example + ".\n"
        );
    }

    private byte[] serialize(final ClassNode cn, final ClassTree tree, final int flags) {
        final ClassWriter writer = buildClassWriter(tree, flags);
        final ClassRemapper remapper = new ClassRemapper(writer, skidfuscator.getClassRemapper());
        cn.node.accept(remapper);
        return RuntimeProtection.instrument(skidfuscator, cn, writer.toByteArray());
    }

    private org.objectweb.asm.tree.ClassNode read(final byte[] bytes) {
        final org.objectweb.asm.tree.ClassNode node = new org.objectweb.asm.tree.ClassNode();
        new ClassReader(bytes).accept(node, 0); // keep code (and frames) intact
        return node;
    }

    private byte[] write(final org.objectweb.asm.tree.ClassNode node, final ClassTree tree) {
        // The prologue is stack-balanced straight-line code prepended at <clinit>
        // entry, so the pre-existing stack-map frames (computed with COMPUTE_FRAMES
        // in pass 1) stay valid: COMPUTE_MAXS only grows maxStack for the extra slots
        // and re-emits the existing frames unchanged. It also avoids re-running frame
        // computation (and its getCommonSuperClass hierarchy resolution) on a
        // freshly-read tree node.
        final ClassWriter writer = buildClassWriter(tree, ClassWriter.COMPUTE_MAXS);
        node.accept(writer);
        return writer.toByteArray();
    }

    private MethodNode clinitOf(final org.objectweb.asm.tree.ClassNode node) {
        for (final MethodNode method : node.methods) {
            if ("<clinit>".equals(method.name) && "()V".equals(method.desc)) {
                return method;
            }
        }
        final MethodNode clinit = new MethodNode(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
        clinit.instructions.add(new InsnNode(Opcodes.RETURN));
        node.methods.add(clinit);
        return clinit;
    }

    /** A class that may host a check and be a verification target. */
    private boolean isEligible(final ClassNode cn, final String finalInternal) {
        if (finalInternal == null || finalInternal.startsWith("sdk/")) {
            return false; // never touch the injected SDK helpers
        }
        if (cn.isVirtual()) {
            return false;
        }
        final int access = cn.node.access;
        return (access & Opcodes.ACC_INTERFACE) == 0
                && (access & Opcodes.ACC_ANNOTATION) == 0
                && (access & Opcodes.ACC_ENUM) == 0;
    }
}
