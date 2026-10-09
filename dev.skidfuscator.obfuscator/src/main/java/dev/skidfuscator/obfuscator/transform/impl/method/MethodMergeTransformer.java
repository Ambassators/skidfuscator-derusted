package dev.skidfuscator.obfuscator.transform.impl.method;

import dev.skidfuscator.obfuscator.Skidfuscator;
import dev.skidfuscator.obfuscator.skidasm.SkidGroup;
import dev.skidfuscator.obfuscator.transform.AbstractTransformer;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.FrameNode;
import org.objectweb.asm.tree.IincInsnNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.LineNumberNode;
import org.objectweb.asm.tree.LookupSwitchInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.TryCatchBlockNode;
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.VarInsnNode;
import org.topdank.byteengineer.commons.data.JarClassData;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Queue;
import java.util.Set;
import java.util.UUID;

/**
 * Late bytecode transformer that aggregates several internal methods into a
 * single "host" method which dispatches to the correct original body at runtime
 * by switching on the interprocedurally-threaded seed key.
 *
 * <p>Skidfuscator's {@code InterproceduralTransformer} appends a trailing
 * {@code int} seed parameter to every threaded group and rewrites every call
 * site to pass {@code group.getPredicate().getPublic()}. That public seed is
 * both the value each body reads internally for its flow predicates and a unique
 * selector per group, so it doubles as a dispatch key: a host that
 * {@code lookupswitch}es on the incoming seed routes seed {@code P_i} to body
 * {@code b_i}, which then reads exactly the seed it was compiled for.</p>
 *
 * <p>Arguments are unified into {@code (byte[], Object[])} exactly like
 * {@code SignatureObfuscationTransformer}; methods are grouped by
 * {@code (owner, returnType, static)} so the host keeps a single return type and
 * never mixes static with instance receivers. The host descriptor is
 * {@code ([B, [Ljava/lang/Object;, I)RET}.</p>
 */
public class MethodMergeTransformer extends AbstractTransformer {
    private static final String BYTE_ARRAY_DESC = "[B";
    private static final String OBJECT_ARRAY_DESC = "[Ljava/lang/Object;";
    private static final String HOST_PREFIX = "skid$merge$";

    /** App, non-exempt, non-native-sensitive classes — the only merge targets. */
    private Map<String, org.objectweb.asm.tree.ClassNode> appClasses;
    /** Every class in the jar (incl. exempt), used for override/handle analysis. */
    private Map<String, org.objectweb.asm.tree.ClassNode> universe;
    /** name+desc -> classes that declare it non-private, for fast override lookup. */
    private Map<String, List<org.objectweb.asm.tree.ClassNode>> declarers;

    private transient int nextScratchLocal;

    public MethodMergeTransformer(final Skidfuscator skidfuscator) {
        super(skidfuscator, "Method Merge");
    }

    @Override
    public boolean isEnabled() {
        return getConfig().getBoolean("enabled", false);
    }

    public void apply() {
        this.appClasses = loadApplicationClasses();
        this.universe = loadAllClasses();
        if (appClasses.isEmpty()) {
            return;
        }
        this.declarers = indexDeclarers(this.universe);
        final Set<MethodKey> handleReferences = collectHandleReferences(this.universe);

        final Map<MethodKey, MergeCandidate> candidates = new LinkedHashMap<>();
        for (SkidGroup group : skidfuscator.getHierarchy().getGroups()) {
            final MergeCandidate candidate = toCandidate(group, handleReferences);
            if (candidate == null) {
                skip();
                continue;
            }
            candidates.put(candidate.key, candidate);
        }

        if (candidates.isEmpty()) {
            return;
        }

        validateCallers(candidates);
        if (candidates.isEmpty()) {
            return;
        }

        final List<Host> hosts = buildHosts(candidates);
        if (hosts.isEmpty()) {
            return;
        }

        final Map<MethodKey, Host> targets = new HashMap<>();
        for (Host host : hosts) {
            for (MergeCandidate member : host.members) {
                targets.put(member.key, host);
            }
        }

        /*
         * Rewrite EVERY call site (including those inside member bodies, which
         * are cloned afterwards) before the bodies are relocated, so an
         * intra-group / recursive call routes to the host too.
         */
        rewriteCallsites(targets);

        for (Host host : hosts) {
            buildHostMethod(host);
            for (MergeCandidate member : host.members) skidfuscator.getDebugMappings().derived(member.raw, host.node);
            host.ownerRaw.methods.add(host.node);
        }

        for (Host host : hosts) {
            for (MergeCandidate member : host.members) {
                host.ownerRaw.methods.remove(member.raw);
                success();
            }
        }
    }

    /* ------------------------------------------------------------------ */
    /* Candidate collection                                                */
    /* ------------------------------------------------------------------ */

    private MergeCandidate toCandidate(final SkidGroup group, final Set<MethodKey> handleReferences) {
        if (!group.isInjectedMethodPredicate()) {
            return null;
        }
        if (group.getMethodNodeList() == null || group.getMethodNodeList().size() != 1) {
            return null;
        }
        if (group.isAnnotation() || group.isEnumerator() || group.isMixin() || group.isNatived()) {
            return null;
        }

        final org.mapleir.asm.MethodNode wrapper = group.first();
        if (wrapper == null || wrapper.node == null || wrapper.owner == null || wrapper.owner.node == null) {
            return null;
        }
        if (skidfuscator.isNativeCandidate(wrapper) || skidfuscator.isRuntimeContract(wrapper)) {
            return null;
        }
        if (skidfuscator.isNativeReferencedMember(
                wrapper.owner.getName(), wrapper.getName(), wrapper.getDesc())
                || skidfuscator.isNativeGeneratedClass(wrapper.owner.getName())
                || skidfuscator.isNativeGeneratedMethod(
                wrapper.owner.getName(), wrapper.getName(), wrapper.getDesc())) {
            return null;
        }
        if (wrapper.owner.isVirtual()) {
            return null;
        }

        final org.objectweb.asm.tree.MethodNode raw = wrapper.node;
        final org.objectweb.asm.tree.ClassNode ownerRaw = wrapper.owner.node;
        final String ownerName = ownerRaw.name;

        if (!appClasses.containsKey(ownerName)) {
            return null;
        }
        if ((ownerRaw.access & Opcodes.ACC_INTERFACE) != 0) {
            return null;
        }
        if (skidfuscator.getExemptAnalysis().isExempt(wrapper)
                || skidfuscator.getExemptAnalysis().isExempt(getClass(), wrapper)) {
            return null;
        }

        final String name = raw.name;
        if ("<init>".equals(name) || "<clinit>".equals(name) || "main".equals(name)) {
            return null;
        }
        if ((raw.access & (Opcodes.ACC_NATIVE | Opcodes.ACC_ABSTRACT
                | Opcodes.ACC_SYNTHETIC | Opcodes.ACC_BRIDGE)) != 0) {
            return null;
        }

        final Type[] args = Type.getArgumentTypes(raw.desc);
        if (args.length == 0 || args[args.length - 1].getSort() != Type.INT) {
            return null;
        }

        final MethodKey key = new MethodKey(ownerName, name, raw.desc);
        if (handleReferences.contains(key)) {
            return null;
        }

        /*
         * private/static methods are invoked by exact reference, so they have no
         * virtual-dispatch family and are always safe to relocate. Any other
         * (overridable) method is rejected if the jar overrides it or it overrides
         * an external contract — in those cases the receiver could resolve to a
         * different body and the merge would diverge from real dispatch.
         */
        final boolean overridable = (raw.access & (Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC)) == 0;
        if (overridable && (isOverriddenInHierarchy(key) || overridesExternalContract(appClasses, key, raw))) {
            return null;
        }

        final boolean isStatic = (raw.access & Opcodes.ACC_STATIC) != 0;
        final int seedSlot = group.getStackHeight();
        final int publicSeed = group.getPredicate().getPublic();
        final String returnDesc = Type.getReturnType(raw.desc).getDescriptor();

        return new MergeCandidate(ownerName, wrapper.owner, ownerRaw, raw, returnDesc, isStatic, seedSlot, publicSeed, key);
    }

    /**
     * Drop any candidate that is invoked from outside the app set (we only
     * rewrite app call sites, so an external caller would dangle after removal)
     * or that has no app caller at all (nothing to reroute).
     */
    private void validateCallers(final Map<MethodKey, MergeCandidate> candidates) {
        final Set<MethodKey> appCalled = new HashSet<>();
        final Set<MethodKey> externallyCalled = new HashSet<>();

        for (org.objectweb.asm.tree.ClassNode classNode : universe.values()) {
            final boolean callerIsApp = appClasses.containsKey(classNode.name);
            for (org.objectweb.asm.tree.MethodNode method : classNode.methods) {
                for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                    if (!(insn instanceof MethodInsnNode)) {
                        continue;
                    }
                    final MethodInsnNode methodInsn = (MethodInsnNode) insn;
                    if (!appClasses.containsKey(methodInsn.owner)) {
                        continue;
                    }
                    final MethodKey resolved = resolveMethod(appClasses, methodInsn.owner, methodInsn.name, methodInsn.desc);
                    if (resolved == null || !candidates.containsKey(resolved)) {
                        continue;
                    }
                    if (callerIsApp) {
                        appCalled.add(resolved);
                    } else {
                        externallyCalled.add(resolved);
                    }
                }
            }
        }

        final Iterator<Map.Entry<MethodKey, MergeCandidate>> iterator = candidates.entrySet().iterator();
        while (iterator.hasNext()) {
            final MethodKey key = iterator.next().getKey();
            if (externallyCalled.contains(key) || !appCalled.contains(key)) {
                iterator.remove();
                skip();
            }
        }
    }

    /* ------------------------------------------------------------------ */
    /* Host grouping & construction                                        */
    /* ------------------------------------------------------------------ */

    private List<Host> buildHosts(final Map<MethodKey, MergeCandidate> candidates) {
        final Map<String, List<MergeCandidate>> byKey = new LinkedHashMap<>();
        for (MergeCandidate candidate : candidates.values()) {
            final String groupKey = candidate.ownerName + '|' + candidate.returnDesc + '|' + candidate.isStatic;
            byKey.computeIfAbsent(groupKey, ignored -> new ArrayList<>()).add(candidate);
        }

        final int maxPerHost = Math.max(2, getConfig().getInt("maxPerHost", 16));
        final int maxHostInsns = Math.max(2000, getConfig().getInt("maxHostInsns", 20000));

        final List<Host> hosts = new ArrayList<>();
        for (List<MergeCandidate> members : byKey.values()) {
            final Set<Integer> seenSeeds = new HashSet<>();
            final List<MergeCandidate> distinct = new ArrayList<>();
            for (MergeCandidate member : members) {
                if (seenSeeds.add(member.publicSeed)) {
                    distinct.add(member);
                } else {
                    fail();
                }
            }

            final List<MergeCandidate> bucket = new ArrayList<>();
            int bucketInsns = 0;
            for (MergeCandidate member : distinct) {
                final int size = member.raw.instructions.size();
                if (!bucket.isEmpty()
                        && (bucket.size() >= maxPerHost || bucketInsns + size > maxHostInsns)) {
                    flushBucket(hosts, bucket);
                    bucket.clear();
                    bucketInsns = 0;
                }
                bucket.add(member);
                bucketInsns += size;
            }
            flushBucket(hosts, bucket);
        }
        return hosts;
    }

    private void flushBucket(final List<Host> hosts, final List<MergeCandidate> bucket) {
        if (bucket.size() < 2) {
            for (int i = 0; i < bucket.size(); i++) {
                skip();
            }
            return;
        }

        final MergeCandidate head = bucket.get(0);
        final int access = head.isStatic
                ? (Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC)
                : (Opcodes.ACC_PUBLIC | Opcodes.ACC_SYNTHETIC);
        final String hostName = HOST_PREFIX + UUID.randomUUID().toString().replace("-", "");
        final String hostDesc = "(" + BYTE_ARRAY_DESC + OBJECT_ARRAY_DESC + "I)" + head.returnDesc;

        hosts.add(new Host(head.ownerName, head.ownerRaw, hostName, hostDesc, access,
                head.isStatic, new ArrayList<>(bucket)));
    }

    private void buildHostMethod(final Host host) {
        final int paramBase = host.isStatic ? 0 : 1;
        final int byteArrayLocal = paramBase;
        final int objectArrayLocal = paramBase + 1;
        final int seedLocal = paramBase + 2;
        final int bodyBase = paramBase + 3;
        final int originalParamBase = host.isStatic ? 0 : 1;

        final List<MergeCandidate> sorted = new ArrayList<>(host.members);
        sorted.sort((a, b) -> Integer.compare(a.publicSeed, b.publicSeed));

        final int[] keys = new int[sorted.size()];
        final LabelNode[] labels = new LabelNode[sorted.size()];
        for (int i = 0; i < sorted.size(); i++) {
            keys[i] = sorted.get(i).publicSeed;
            labels[i] = new LabelNode();
        }
        final LabelNode defaultLabel = new LabelNode();

        final InsnList out = new InsnList();
        final List<TryCatchBlockNode> tryCatchBlocks = new ArrayList<>();

        out.add(new VarInsnNode(Opcodes.ILOAD, seedLocal));
        out.add(new LookupSwitchInsnNode(defaultLabel, keys, labels));

        int maxBodyLocals = 0;
        int maxBodyStack = 0;
        for (int i = 0; i < sorted.size(); i++) {
            final MergeCandidate member = sorted.get(i);
            out.add(labels[i]);

            if (!host.isStatic) {
                out.add(new VarInsnNode(Opcodes.ALOAD, 0));
                out.add(new VarInsnNode(Opcodes.ASTORE, bodyBase));
            }

            final Type[] allArgs = Type.getArgumentTypes(member.raw.desc);
            final Type[] realArgs = Arrays.copyOf(allArgs, allArgs.length - 1);
            emitUnpackInto(out, byteArrayLocal, objectArrayLocal, realArgs, bodyBase + originalParamBase);

            out.add(new VarInsnNode(Opcodes.ILOAD, seedLocal));
            out.add(new VarInsnNode(Opcodes.ISTORE, bodyBase + member.seedSlot));

            cloneBodyInto(out, tryCatchBlocks, member.raw, bodyBase);

            maxBodyLocals = Math.max(maxBodyLocals, Math.max(member.raw.maxLocals, computeLocalLimit(member.raw)));
            maxBodyStack = Math.max(maxBodyStack, member.raw.maxStack);
        }

        out.add(defaultLabel);
        out.add(new TypeInsnNode(Opcodes.NEW, "java/lang/IllegalStateException"));
        out.add(new InsnNode(Opcodes.DUP));
        out.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, "java/lang/IllegalStateException", "<init>", "()V", false));
        out.add(new InsnNode(Opcodes.ATHROW));

        final org.objectweb.asm.tree.MethodNode node =
                new org.objectweb.asm.tree.MethodNode(host.access, host.hostName, host.hostDesc, null, null);
        node.instructions = out;
        node.tryCatchBlocks = tryCatchBlocks;
        node.maxLocals = bodyBase + maxBodyLocals + 4;
        node.maxStack = Math.max(maxBodyStack, 8) + 4;

        host.node = node;
    }

    private void emitUnpackInto(final InsnList insns,
                                final int byteArrayLocal,
                                final int objectArrayLocal,
                                final Type[] realArgs,
                                final int targetBase) {
        int byteOffset = 0;
        int objectOffset = 0;
        int target = targetBase;
        for (Type type : realArgs) {
            if (isPrimitive(type)) {
                byteOffset = emitPrimitiveUnpack(insns, byteArrayLocal, byteOffset, type);
                insns.add(new VarInsnNode(type.getOpcode(Opcodes.ISTORE), target));
            } else {
                insns.add(new VarInsnNode(Opcodes.ALOAD, objectArrayLocal));
                pushInt(insns, objectOffset++);
                insns.add(new InsnNode(Opcodes.AALOAD));
                emitCheckCast(insns, type);
                insns.add(new VarInsnNode(Opcodes.ASTORE, target));
            }
            target += type.getSize();
        }
    }

    private void cloneBodyInto(final InsnList out,
                               final List<TryCatchBlockNode> tryCatchBlocks,
                               final org.objectweb.asm.tree.MethodNode raw,
                               final int bodyBase) {
        final Map<LabelNode, LabelNode> labelMap = new HashMap<>();
        for (AbstractInsnNode insn = raw.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn instanceof LabelNode) {
                labelMap.put((LabelNode) insn, new LabelNode());
            }
        }

        for (AbstractInsnNode insn = raw.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn instanceof FrameNode || insn instanceof LineNumberNode) {
                continue;
            }
            final AbstractInsnNode cloned = insn.clone(labelMap);
            if (cloned instanceof VarInsnNode) {
                ((VarInsnNode) cloned).var += bodyBase;
            } else if (cloned instanceof IincInsnNode) {
                ((IincInsnNode) cloned).var += bodyBase;
            }
            skidfuscator.getDebugMappings().copied(insn, cloned);
            out.add(cloned);
        }

        if (raw.tryCatchBlocks != null) {
            for (TryCatchBlockNode tcb : raw.tryCatchBlocks) {
                tryCatchBlocks.add(new TryCatchBlockNode(
                        labelMap.get(tcb.start),
                        labelMap.get(tcb.end),
                        labelMap.get(tcb.handler),
                        tcb.type
                ));
            }
        }
    }

    /* ------------------------------------------------------------------ */
    /* Call-site rewriting                                                 */
    /* ------------------------------------------------------------------ */

    private void rewriteCallsites(final Map<MethodKey, Host> targets) {
        for (org.objectweb.asm.tree.ClassNode classNode : appClasses.values()) {
            for (org.objectweb.asm.tree.MethodNode method : classNode.methods) {
                boolean changed = false;
                method.maxLocals = Math.max(method.maxLocals, computeLocalLimit(method));
                nextScratchLocal = method.maxLocals;

                for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                    if (!(insn instanceof MethodInsnNode)) {
                        continue;
                    }
                    final MethodInsnNode methodInsn = (MethodInsnNode) insn;
                    if (!appClasses.containsKey(methodInsn.owner)) {
                        continue;
                    }
                    final MethodKey resolved = resolveMethod(appClasses, methodInsn.owner, methodInsn.name, methodInsn.desc);
                    final Host host = resolved == null ? null : targets.get(resolved);
                    if (host == null) {
                        continue;
                    }

                    final Type[] allArgs = Type.getArgumentTypes(methodInsn.desc);
                    final Type[] realArgs = Arrays.copyOf(allArgs, allArgs.length - 1);
                    final int seedScratch = nextScratchLocal++;

                    final InsnList replacement = new InsnList();
                    replacement.add(new VarInsnNode(Opcodes.ISTORE, seedScratch));
                    replacement.add(packArguments(realArgs, host.isStatic));
                    replacement.add(new VarInsnNode(Opcodes.ILOAD, seedScratch));
                    method.instructions.insertBefore(methodInsn, replacement);

                    methodInsn.setOpcode(host.isStatic ? Opcodes.INVOKESTATIC : Opcodes.INVOKEVIRTUAL);
                    methodInsn.owner = host.ownerName;
                    methodInsn.name = host.hostName;
                    methodInsn.desc = host.hostDesc;
                    methodInsn.itf = false;
                    changed = true;
                }

                if (changed) {
                    method.maxLocals = Math.max(method.maxLocals, nextScratchLocal);
                    method.maxStack = Math.max(method.maxStack, 8);
                    method.localVariables = null;
                    method.signature = null;
                }
            }
        }
    }

    private InsnList packArguments(final Type[] argumentTypes, final boolean isStatic) {
        final InsnList insns = new InsnList();
        final int[] argLocals = new int[argumentTypes.length];
        int next = nextScratchLocal;

        for (int i = argumentTypes.length - 1; i >= 0; i--) {
            argLocals[i] = next;
            next += argumentTypes[i].getSize();
            insns.add(new VarInsnNode(argumentTypes[i].getOpcode(Opcodes.ISTORE), argLocals[i]));
        }

        int receiverLocal = -1;
        if (!isStatic) {
            receiverLocal = next++;
            insns.add(new VarInsnNode(Opcodes.ASTORE, receiverLocal));
        }

        final int primitiveSize = primitiveByteSize(argumentTypes);
        final int referenceCount = referenceCount(argumentTypes);
        final int byteArrayLocal = next++;
        final int objectArrayLocal = next++;
        nextScratchLocal = Math.max(nextScratchLocal, next);

        pushInt(insns, primitiveSize);
        insns.add(new IntInsnNode(Opcodes.NEWARRAY, Opcodes.T_BYTE));
        insns.add(new VarInsnNode(Opcodes.ASTORE, byteArrayLocal));

        pushInt(insns, referenceCount);
        insns.add(new TypeInsnNode(Opcodes.ANEWARRAY, "java/lang/Object"));
        insns.add(new VarInsnNode(Opcodes.ASTORE, objectArrayLocal));

        int byteOffset = 0;
        int objectOffset = 0;
        for (int i = 0; i < argumentTypes.length; i++) {
            final Type type = argumentTypes[i];
            if (isPrimitive(type)) {
                byteOffset = emitPrimitivePack(insns, byteArrayLocal, byteOffset, type, argLocals[i]);
            } else {
                insns.add(new VarInsnNode(Opcodes.ALOAD, objectArrayLocal));
                pushInt(insns, objectOffset++);
                insns.add(new VarInsnNode(Opcodes.ALOAD, argLocals[i]));
                insns.add(new InsnNode(Opcodes.AASTORE));
            }
        }

        if (!isStatic) {
            insns.add(new VarInsnNode(Opcodes.ALOAD, receiverLocal));
        }
        insns.add(new VarInsnNode(Opcodes.ALOAD, byteArrayLocal));
        insns.add(new VarInsnNode(Opcodes.ALOAD, objectArrayLocal));

        return insns;
    }

    /* ------------------------------------------------------------------ */
    /* Class loading / indexing                                            */
    /* ------------------------------------------------------------------ */

    private Map<String, org.objectweb.asm.tree.ClassNode> loadApplicationClasses() {
        final Map<String, org.objectweb.asm.tree.ClassNode> classes = new LinkedHashMap<>();
        for (JarClassData classData : skidfuscator.getJarContents().getClassContents()) {
            final org.mapleir.asm.ClassNode classNode = classData.getClassNode();
            if (classNode == null || classNode.node == null) {
                continue;
            }
            if (isNativeSensitiveClass(classNode.node.name)
                    || skidfuscator.isNativeGeneratedClass(classNode.node.name)) {
                continue;
            }
            if (skidfuscator.getExemptAnalysis().isExempt(classNode)
                    || skidfuscator.getExemptAnalysis().isExempt(getClass(), classNode)) {
                continue;
            }
            classes.put(classNode.node.name, classNode.node);
        }
        return classes;
    }

    private Map<String, org.objectweb.asm.tree.ClassNode> loadAllClasses() {
        final Map<String, org.objectweb.asm.tree.ClassNode> all = new LinkedHashMap<>();
        for (JarClassData classData : skidfuscator.getJarContents().getClassContents()) {
            final org.mapleir.asm.ClassNode classNode = classData.getClassNode();
            if (classNode == null || classNode.node == null || isNativeSensitiveClass(classNode.node.name)
                    || skidfuscator.isNativeGeneratedClass(classNode.node.name)) {
                continue;
            }
            all.put(classNode.node.name, classNode.node);
        }
        return all;
    }

    private boolean isNativeSensitiveClass(final String name) {
        return name != null
                && (name.startsWith("org/jnativehook/") || name.startsWith("com/sun/jna/"));
    }

    private Map<String, List<org.objectweb.asm.tree.ClassNode>> indexDeclarers(
            final Map<String, org.objectweb.asm.tree.ClassNode> all) {
        final Map<String, List<org.objectweb.asm.tree.ClassNode>> index = new HashMap<>();
        for (org.objectweb.asm.tree.ClassNode classNode : all.values()) {
            for (org.objectweb.asm.tree.MethodNode method : classNode.methods) {
                if ((method.access & Opcodes.ACC_PRIVATE) != 0) {
                    continue;
                }
                index.computeIfAbsent(method.name + method.desc, ignored -> new ArrayList<>()).add(classNode);
            }
        }
        return index;
    }

    private Set<MethodKey> collectHandleReferences(final Map<String, org.objectweb.asm.tree.ClassNode> classes) {
        final Set<MethodKey> references = new HashSet<>();
        for (org.objectweb.asm.tree.ClassNode classNode : classes.values()) {
            for (org.objectweb.asm.tree.MethodNode method : classNode.methods) {
                for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                    if (insn instanceof InvokeDynamicInsnNode) {
                        final InvokeDynamicInsnNode indy = (InvokeDynamicInsnNode) insn;
                        addHandleReference(classes, references, indy.bsm);
                        for (Object arg : indy.bsmArgs) {
                            if (arg instanceof Handle) {
                                addHandleReference(classes, references, (Handle) arg);
                            }
                        }
                    } else if (insn instanceof LdcInsnNode) {
                        final Object cst = ((LdcInsnNode) insn).cst;
                        if (cst instanceof Handle) {
                            addHandleReference(classes, references, (Handle) cst);
                        }
                    }
                }
            }
        }
        return references;
    }

    private void addHandleReference(final Map<String, org.objectweb.asm.tree.ClassNode> classes,
                                    final Set<MethodKey> references,
                                    final Handle handle) {
        if (handle == null || !classes.containsKey(handle.getOwner())) {
            return;
        }
        final MethodKey resolved = resolveMethod(classes, handle.getOwner(), handle.getName(), handle.getDesc());
        if (resolved != null) {
            references.add(resolved);
        }
    }

    /* ------------------------------------------------------------------ */
    /* Override / dispatch safety (mirrors SignatureObfuscationTransformer)*/
    /* ------------------------------------------------------------------ */

    private boolean isOverriddenInHierarchy(final MethodKey key) {
        final List<org.objectweb.asm.tree.ClassNode> list = declarers.get(key.name + key.desc);
        if (list == null) {
            return false;
        }
        for (org.objectweb.asm.tree.ClassNode candidate : list) {
            if (candidate.name.equals(key.owner)) {
                continue;
            }
            if (isSubtypeOf(candidate.name, key.owner, new HashSet<>())) {
                return true;
            }
        }
        return false;
    }

    private boolean isSubtypeOf(final String child, final String ancestor, final Set<String> visited) {
        if (child == null || !visited.add(child)) {
            return false;
        }
        if (child.equals(ancestor)) {
            return true;
        }
        final org.objectweb.asm.tree.ClassNode node = resolveNode(child);
        if (node == null) {
            return false;
        }
        if (node.superName != null && isSubtypeOf(node.superName, ancestor, visited)) {
            return true;
        }
        for (String itf : node.interfaces) {
            if (isSubtypeOf(itf, ancestor, visited)) {
                return true;
            }
        }
        return false;
    }

    private org.objectweb.asm.tree.ClassNode resolveNode(final String name) {
        final org.objectweb.asm.tree.ClassNode appNode = universe.get(name);
        if (appNode != null) {
            return appNode;
        }
        final org.mapleir.asm.ClassNode library = skidfuscator.getClassSource().findClassNode(name);
        return library == null ? null : library.node;
    }

    private boolean overridesExternalContract(final Map<String, org.objectweb.asm.tree.ClassNode> appClasses,
                                              final MethodKey key,
                                              final org.objectweb.asm.tree.MethodNode method) {
        if ((method.access & (Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC)) != 0) {
            return false;
        }

        if (isObjectContract(key.name, key.desc)) {
            return true;
        }

        final org.objectweb.asm.tree.ClassNode owner = appClasses.get(key.owner);
        if (owner == null) {
            return true;
        }

        final Queue<String> pending = new ArrayDeque<>();
        if (owner.superName != null) {
            pending.add(owner.superName);
        }
        pending.addAll(owner.interfaces);

        final Set<String> visited = new HashSet<>();
        while (!pending.isEmpty()) {
            final String name = pending.remove();
            if (name == null || !visited.add(name) || "java/lang/Object".equals(name)) {
                continue;
            }

            final org.objectweb.asm.tree.ClassNode appNode = appClasses.get(name);
            if (appNode != null) {
                if (declaresMethod(appNode, key.name, key.desc)) {
                    return true;
                }
                if (appNode.superName != null) {
                    pending.add(appNode.superName);
                }
                pending.addAll(appNode.interfaces);
                continue;
            }

            final org.mapleir.asm.ClassNode externalNode = skidfuscator.getClassSource().findClassNode(name);
            if (externalNode == null || externalNode.node == null) {
                return true;
            }
            if (declaresMethod(externalNode.node, key.name, key.desc)) {
                return true;
            }
            if (externalNode.node.superName != null) {
                pending.add(externalNode.node.superName);
            }
            pending.addAll(externalNode.node.interfaces);
        }

        return false;
    }

    private boolean declaresMethod(final org.objectweb.asm.tree.ClassNode classNode,
                                   final String name,
                                   final String desc) {
        for (org.objectweb.asm.tree.MethodNode method : classNode.methods) {
            if (method.name.equals(name) && method.desc.equals(desc)
                    && (method.access & Opcodes.ACC_PRIVATE) == 0) {
                return true;
            }
        }
        return false;
    }

    private boolean isObjectContract(final String name, final String desc) {
        return ("toString".equals(name) && "()Ljava/lang/String;".equals(desc))
                || ("hashCode".equals(name) && "()I".equals(desc))
                || ("equals".equals(name) && "(Ljava/lang/Object;)Z".equals(desc))
                || ("clone".equals(name) && "()Ljava/lang/Object;".equals(desc))
                || ("finalize".equals(name) && "()V".equals(desc));
    }

    private MethodKey resolveMethod(final Map<String, org.objectweb.asm.tree.ClassNode> classes,
                                    final String owner,
                                    final String name,
                                    final String desc) {
        return resolveMethod(classes, owner, name, desc, new HashSet<>());
    }

    private MethodKey resolveMethod(final Map<String, org.objectweb.asm.tree.ClassNode> classes,
                                    final String owner,
                                    final String name,
                                    final String desc,
                                    final Set<String> visited) {
        if (owner == null || !visited.add(owner)) {
            return null;
        }
        final org.objectweb.asm.tree.ClassNode classNode = classes.get(owner);
        if (classNode == null) {
            return null;
        }
        for (org.objectweb.asm.tree.MethodNode method : classNode.methods) {
            if (method.name.equals(name) && method.desc.equals(desc)) {
                return new MethodKey(owner, name, desc);
            }
        }
        for (String itf : classNode.interfaces) {
            final MethodKey resolved = resolveMethod(classes, itf, name, desc, visited);
            if (resolved != null) {
                return resolved;
            }
        }
        return resolveMethod(classes, classNode.superName, name, desc, visited);
    }

    /* ------------------------------------------------------------------ */
    /* Primitive pack / unpack (mirrors SignatureObfuscationTransformer)   */
    /* ------------------------------------------------------------------ */

    private int computeLocalLimit(final org.objectweb.asm.tree.MethodNode method) {
        int limit = argumentLocalLimit(method);
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn instanceof VarInsnNode) {
                final VarInsnNode varInsn = (VarInsnNode) insn;
                limit = Math.max(limit, varInsn.var + localSize(varInsn.getOpcode()));
            } else if (insn instanceof IincInsnNode) {
                final IincInsnNode iincInsn = (IincInsnNode) insn;
                limit = Math.max(limit, iincInsn.var + 1);
            }
        }
        return limit;
    }

    private int argumentLocalLimit(final org.objectweb.asm.tree.MethodNode method) {
        int limit = (method.access & Opcodes.ACC_STATIC) == 0 ? 1 : 0;
        for (Type type : Type.getArgumentTypes(method.desc)) {
            limit += type.getSize();
        }
        return limit;
    }

    private int localSize(final int opcode) {
        switch (opcode) {
            case Opcodes.LLOAD:
            case Opcodes.LSTORE:
            case Opcodes.DLOAD:
            case Opcodes.DSTORE:
                return 2;
            default:
                return 1;
        }
    }

    private int emitPrimitivePack(final InsnList insns,
                                  final int byteArrayLocal,
                                  final int offset,
                                  final Type type,
                                  final int local) {
        switch (type.getSort()) {
            case Type.BOOLEAN:
            case Type.BYTE:
                emitByteStore(insns, byteArrayLocal, offset, () -> insns.add(new VarInsnNode(Opcodes.ILOAD, local)));
                return offset + 1;
            case Type.CHAR:
            case Type.SHORT:
                emitIntByteStores(insns, byteArrayLocal, offset, local, 2);
                return offset + 2;
            case Type.INT:
                emitIntByteStores(insns, byteArrayLocal, offset, local, 4);
                return offset + 4;
            case Type.FLOAT: {
                final int temp = nextScratchLocal++;
                insns.add(new VarInsnNode(Opcodes.FLOAD, local));
                insns.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Float", "floatToIntBits", "(F)I", false));
                insns.add(new VarInsnNode(Opcodes.ISTORE, temp));
                emitIntByteStores(insns, byteArrayLocal, offset, temp, 4);
                return offset + 4;
            }
            case Type.LONG:
                emitLongByteStores(insns, byteArrayLocal, offset, local);
                return offset + 8;
            case Type.DOUBLE: {
                final int temp = nextScratchLocal;
                nextScratchLocal += 2;
                insns.add(new VarInsnNode(Opcodes.DLOAD, local));
                insns.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Double", "doubleToLongBits", "(D)J", false));
                insns.add(new VarInsnNode(Opcodes.LSTORE, temp));
                emitLongByteStores(insns, byteArrayLocal, offset, temp);
                return offset + 8;
            }
            default:
                throw new IllegalArgumentException("Unsupported primitive type: " + type);
        }
    }

    private int emitPrimitiveUnpack(final InsnList insns,
                                    final int byteArrayLocal,
                                    final int offset,
                                    final Type type) {
        switch (type.getSort()) {
            case Type.BOOLEAN:
            case Type.BYTE:
                emitLoadMaskedByte(insns, byteArrayLocal, offset, false);
                if (type.getSort() == Type.BYTE) {
                    insns.add(new InsnNode(Opcodes.I2B));
                }
                return offset + 1;
            case Type.CHAR:
                emitLoadInt(insns, byteArrayLocal, offset, 2);
                insns.add(new InsnNode(Opcodes.I2C));
                return offset + 2;
            case Type.SHORT:
                emitLoadInt(insns, byteArrayLocal, offset, 2);
                insns.add(new InsnNode(Opcodes.I2S));
                return offset + 2;
            case Type.INT:
                emitLoadInt(insns, byteArrayLocal, offset, 4);
                return offset + 4;
            case Type.FLOAT:
                emitLoadInt(insns, byteArrayLocal, offset, 4);
                insns.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Float", "intBitsToFloat", "(I)F", false));
                return offset + 4;
            case Type.LONG:
                emitLoadLong(insns, byteArrayLocal, offset);
                return offset + 8;
            case Type.DOUBLE:
                emitLoadLong(insns, byteArrayLocal, offset);
                insns.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/Double", "longBitsToDouble", "(J)D", false));
                return offset + 8;
            default:
                throw new IllegalArgumentException("Unsupported primitive type: " + type);
        }
    }

    private void emitByteStore(final InsnList insns,
                               final int arrayLocal,
                               final int index,
                               final Runnable valueEmitter) {
        insns.add(new VarInsnNode(Opcodes.ALOAD, arrayLocal));
        pushInt(insns, index);
        valueEmitter.run();
        insns.add(new InsnNode(Opcodes.BASTORE));
    }

    private void emitIntByteStores(final InsnList insns,
                                   final int arrayLocal,
                                   final int offset,
                                   final int local,
                                   final int width) {
        for (int i = 0; i < width; i++) {
            final int shift = (width - 1 - i) * 8;
            emitByteStore(insns, arrayLocal, offset + i, () -> {
                insns.add(new VarInsnNode(Opcodes.ILOAD, local));
                if (shift != 0) {
                    pushInt(insns, shift);
                    insns.add(new InsnNode(Opcodes.IUSHR));
                }
            });
        }
    }

    private void emitLongByteStores(final InsnList insns,
                                    final int arrayLocal,
                                    final int offset,
                                    final int local) {
        for (int i = 0; i < 8; i++) {
            final int shift = (7 - i) * 8;
            emitByteStore(insns, arrayLocal, offset + i, () -> {
                insns.add(new VarInsnNode(Opcodes.LLOAD, local));
                if (shift != 0) {
                    pushInt(insns, shift);
                    insns.add(new InsnNode(Opcodes.LUSHR));
                }
                insns.add(new InsnNode(Opcodes.L2I));
            });
        }
    }

    private void emitLoadMaskedByte(final InsnList insns,
                                    final int arrayLocal,
                                    final int index,
                                    final boolean mask) {
        insns.add(new VarInsnNode(Opcodes.ALOAD, arrayLocal));
        pushInt(insns, index);
        insns.add(new InsnNode(Opcodes.BALOAD));
        if (mask) {
            pushInt(insns, 0xFF);
            insns.add(new InsnNode(Opcodes.IAND));
        }
    }

    private void emitLoadInt(final InsnList insns,
                             final int arrayLocal,
                             final int offset,
                             final int width) {
        for (int i = 0; i < width; i++) {
            emitLoadMaskedByte(insns, arrayLocal, offset + i, true);
            final int shift = (width - 1 - i) * 8;
            if (shift != 0) {
                pushInt(insns, shift);
                insns.add(new InsnNode(Opcodes.ISHL));
            }
            if (i != 0) {
                insns.add(new InsnNode(Opcodes.IOR));
            }
        }
    }

    private void emitLoadLong(final InsnList insns,
                              final int arrayLocal,
                              final int offset) {
        for (int i = 0; i < 8; i++) {
            emitLoadMaskedByte(insns, arrayLocal, offset + i, true);
            insns.add(new InsnNode(Opcodes.I2L));
            final int shift = (7 - i) * 8;
            if (shift != 0) {
                pushInt(insns, shift);
                insns.add(new InsnNode(Opcodes.LSHL));
            }
            if (i != 0) {
                insns.add(new InsnNode(Opcodes.LOR));
            }
        }
    }

    private void emitCheckCast(final InsnList insns, final Type type) {
        if (type.getSort() == Type.OBJECT) {
            insns.add(new TypeInsnNode(Opcodes.CHECKCAST, type.getInternalName()));
        } else if (type.getSort() == Type.ARRAY) {
            insns.add(new TypeInsnNode(Opcodes.CHECKCAST, type.getDescriptor()));
        }
    }

    private boolean isPrimitive(final Type type) {
        final int sort = type.getSort();
        return sort >= Type.BOOLEAN && sort <= Type.DOUBLE;
    }

    private int primitiveByteSize(final Type[] types) {
        int size = 0;
        for (Type type : types) {
            switch (type.getSort()) {
                case Type.BOOLEAN:
                case Type.BYTE:
                    size += 1;
                    break;
                case Type.CHAR:
                case Type.SHORT:
                    size += 2;
                    break;
                case Type.INT:
                case Type.FLOAT:
                    size += 4;
                    break;
                case Type.LONG:
                case Type.DOUBLE:
                    size += 8;
                    break;
                default:
                    break;
            }
        }
        return size;
    }

    private int referenceCount(final Type[] types) {
        int count = 0;
        for (Type type : types) {
            if (!isPrimitive(type)) {
                count++;
            }
        }
        return count;
    }

    private void pushInt(final InsnList insns, final int value) {
        if (value >= -1 && value <= 5) {
            insns.add(new InsnNode(Opcodes.ICONST_0 + value));
        } else if (value >= Byte.MIN_VALUE && value <= Byte.MAX_VALUE) {
            insns.add(new IntInsnNode(Opcodes.BIPUSH, value));
        } else if (value >= Short.MIN_VALUE && value <= Short.MAX_VALUE) {
            insns.add(new IntInsnNode(Opcodes.SIPUSH, value));
        } else {
            insns.add(new LdcInsnNode(value));
        }
    }

    /* ------------------------------------------------------------------ */
    /* Data holders                                                        */
    /* ------------------------------------------------------------------ */

    private static final class MergeCandidate {
        private final String ownerName;
        private final org.mapleir.asm.ClassNode ownerWrapper;
        private final org.objectweb.asm.tree.ClassNode ownerRaw;
        private final org.objectweb.asm.tree.MethodNode raw;
        private final String returnDesc;
        private final boolean isStatic;
        private final int seedSlot;
        private final int publicSeed;
        private final MethodKey key;

        private MergeCandidate(final String ownerName,
                               final org.mapleir.asm.ClassNode ownerWrapper,
                               final org.objectweb.asm.tree.ClassNode ownerRaw,
                               final org.objectweb.asm.tree.MethodNode raw,
                               final String returnDesc,
                               final boolean isStatic,
                               final int seedSlot,
                               final int publicSeed,
                               final MethodKey key) {
            this.ownerName = ownerName;
            this.ownerWrapper = ownerWrapper;
            this.ownerRaw = ownerRaw;
            this.raw = raw;
            this.returnDesc = returnDesc;
            this.isStatic = isStatic;
            this.seedSlot = seedSlot;
            this.publicSeed = publicSeed;
            this.key = key;
        }
    }

    private static final class Host {
        private final String ownerName;
        private final org.objectweb.asm.tree.ClassNode ownerRaw;
        private final String hostName;
        private final String hostDesc;
        private final int access;
        private final boolean isStatic;
        private final List<MergeCandidate> members;
        private org.objectweb.asm.tree.MethodNode node;

        private Host(final String ownerName,
                     final org.objectweb.asm.tree.ClassNode ownerRaw,
                     final String hostName,
                     final String hostDesc,
                     final int access,
                     final boolean isStatic,
                     final List<MergeCandidate> members) {
            this.ownerName = ownerName;
            this.ownerRaw = ownerRaw;
            this.hostName = hostName;
            this.hostDesc = hostDesc;
            this.access = access;
            this.isStatic = isStatic;
            this.members = members;
        }
    }

    private static final class MethodKey {
        private final String owner;
        private final String name;
        private final String desc;

        private MethodKey(final String owner, final String name, final String desc) {
            this.owner = owner;
            this.name = name;
            this.desc = desc;
        }

        @Override
        public boolean equals(final Object o) {
            if (this == o) return true;
            if (!(o instanceof MethodKey)) return false;
            final MethodKey methodKey = (MethodKey) o;
            return Objects.equals(owner, methodKey.owner)
                    && Objects.equals(name, methodKey.name)
                    && Objects.equals(desc, methodKey.desc);
        }

        @Override
        public int hashCode() {
            return Objects.hash(owner, name, desc);
        }
    }
}
