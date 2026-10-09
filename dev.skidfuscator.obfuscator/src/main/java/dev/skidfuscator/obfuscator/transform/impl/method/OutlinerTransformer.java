package dev.skidfuscator.obfuscator.transform.impl.method;

import dev.skidfuscator.obfuscator.Skidfuscator;
import dev.skidfuscator.obfuscator.transform.AbstractTransformer;
import org.objectweb.asm.ConstantDynamic;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FrameNode;
import org.objectweb.asm.tree.IincInsnNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.LineNumberNode;
import org.objectweb.asm.tree.LookupSwitchInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TableSwitchInsnNode;
import org.objectweb.asm.tree.TryCatchBlockNode;
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.VarInsnNode;
import org.objectweb.asm.tree.analysis.Analyzer;
import org.objectweb.asm.tree.analysis.AnalyzerException;
import org.objectweb.asm.tree.analysis.BasicValue;
import org.objectweb.asm.tree.analysis.BasicVerifier;
import org.objectweb.asm.tree.analysis.Frame;
import org.topdank.byteengineer.commons.data.JarClassData;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * Late raw-ASM outliner. It extracts small, verifier-friendly straight-line
 * instruction ranges into synthetic private static methods and replaces each
 * range with an {@code INVOKESTATIC}. Locals and operand-stack values crossing
 * the boundary are transported through object arrays so multiple inputs and
 * outputs remain possible while ClassWriter recomputes frames at dump time.
 */
public class OutlinerTransformer extends AbstractTransformer {
    private static final String OBJECT = "java/lang/Object";
    private static final String OBJECT_ARRAY = "[Ljava/lang/Object;";
    private static final String OUTLINE_DESC = "([Ljava/lang/Object;)[Ljava/lang/Object;";
    private static final String OUTLINE_PREFIX = "skid$outline$";

    private int nextScratchLocal;

    public OutlinerTransformer(final Skidfuscator skidfuscator) {
        super(skidfuscator, "Outliner");
    }

    @Override
    public boolean isEnabled() {
        return getConfig().getBoolean("enabled", false);
    }

    public void apply() {
        final int minInstructions = Math.max(2, getConfig().getInt("minInstructions", 4));
        final int maxInstructions = Math.max(minInstructions, getConfig().getInt("maxInstructions", 14));
        final int maxPerMethod = Math.max(1, getConfig().getInt("maxPerMethod", 1));
        final int maxInputs = Math.max(1, getConfig().getInt("maxInputs", 8));
        final int maxOutputs = Math.max(1, getConfig().getInt("maxOutputs", 6));
        final int maxStackValues = Math.max(0, getConfig().getInt("maxStackValues", 3));

        for (JarClassData classData : skidfuscator.getJarContents().getClassContents()) {
            final org.mapleir.asm.ClassNode wrapper = classData.getClassNode();
            if (wrapper == null || wrapper.node == null) {
                continue;
            }

            final ClassNode classNode = wrapper.node;
            if (wrapper.isVirtual() || (classNode.access & Opcodes.ACC_INTERFACE) != 0
                    || skidfuscator.isNativeGeneratedClass(classNode.name) || isClassExempt(wrapper)) {
                skip();
                continue;
            }

            processClass(wrapper, classNode, minInstructions, maxInstructions, maxPerMethod,
                    maxInputs, maxOutputs, maxStackValues);
        }
    }

    private void processClass(final org.mapleir.asm.ClassNode wrapper,
                              final ClassNode classNode,
                              final int minInstructions,
                              final int maxInstructions,
                              final int maxPerMethod,
                              final int maxInputs,
                              final int maxOutputs,
                              final int maxStackValues) {
        final List<MethodNode> helpers = new ArrayList<>();
        final List<MethodNode> methods = new ArrayList<>(classNode.methods);

        for (MethodNode method : methods) {
            if (!isEligibleMethod(wrapper, method)) {
                skip();
                continue;
            }

            int outlined = 0;
            while (outlined < maxPerMethod) {
                final Candidate candidate = findCandidate(classNode, method, minInstructions, maxInstructions,
                        maxInputs, maxOutputs, maxStackValues);
                if (candidate == null) {
                    if (outlined == 0) {
                        skip();
                    }
                    break;
                }

                candidate.helperName = uniqueMethodName(classNode, OUTLINE_PREFIX, OUTLINE_DESC);
                candidate.helper = buildHelper(candidate);
                skidfuscator.getDebugMappings().derived(method, candidate.helper);
                rewriteOriginal(classNode, method, candidate);
                helpers.add(candidate.helper);
                outlined++;
                success();
            }
        }

        classNode.methods.addAll(helpers);
    }

    private boolean isEligibleMethod(final org.mapleir.asm.ClassNode owner, final MethodNode method) {
        if (method.instructions == null || method.instructions.size() == 0) {
            return false;
        }
        if (skidfuscator.isNativeCandidate(owner.getName(), method.name, method.desc)) {
            return false;
        }
        if (skidfuscator.isNativeGeneratedClass(owner.getName())
                || skidfuscator.isNativeGeneratedMethod(owner.getName(), method.name, method.desc)) {
            return false;
        }
        if ((method.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE | Opcodes.ACC_SYNTHETIC | Opcodes.ACC_BRIDGE)) != 0) {
            return false;
        }
        if ("<init>".equals(method.name) || "<clinit>".equals(method.name)) {
            return false;
        }
        final org.mapleir.asm.MethodNode wrapped = findWrappedMethod(owner, method);
        return wrapped == null
                || (!skidfuscator.getExemptAnalysis().isExempt(wrapped)
                && !skidfuscator.getExemptAnalysis().isExempt(getClass(), wrapped));
    }

    private Candidate findCandidate(final ClassNode classNode,
                                    final MethodNode method,
                                    final int minInstructions,
                                    final int maxInstructions,
                                    final int maxInputs,
                                    final int maxOutputs,
                                    final int maxStackValues) {
        final Analysis analysis = analyze(classNode, method);
        if (analysis == null || analysis.executable.size() < minInstructions) {
            return null;
        }

        final int upper = Math.min(maxInstructions, analysis.executable.size());
        for (int start = 0; start < analysis.executable.size(); start++) {
            for (int size = upper; size >= minInstructions; size--) {
                final int end = start + size - 1;
                if (end >= analysis.executable.size()) {
                    continue;
                }
                if (!isSafeRange(analysis, start, end)) {
                    continue;
                }

                final Candidate candidate = buildCandidate(analysis, start, end, maxInputs, maxOutputs, maxStackValues);
                if (candidate != null) {
                    return candidate;
                }
            }
        }
        return null;
    }

    private Analysis analyze(final ClassNode classNode, final MethodNode method) {
        final Analyzer<BasicValue> analyzer = new Analyzer<>(new BasicVerifier());
        final Frame<BasicValue>[] frames;
        try {
            frames = analyzer.analyze(classNode.name, method);
        } catch (AnalyzerException ex) {
            fail();
            return null;
        }

        final List<AbstractInsnNode> all = new ArrayList<>();
        final Map<AbstractInsnNode, Integer> fullIndexes = new HashMap<>();
        for (int i = 0; i < method.instructions.size(); i++) {
            final AbstractInsnNode insn = method.instructions.get(i);
            all.add(insn);
            fullIndexes.put(insn, i);
        }

        final List<AbstractInsnNode> executable = new ArrayList<>();
        final Map<AbstractInsnNode, Integer> executableIndexes = new HashMap<>();
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn.getOpcode() >= 0) {
                executableIndexes.put(insn, executable.size());
                executable.add(insn);
            }
        }

        final boolean[] protectedExecutable = new boolean[executable.size()];
        final Set<LabelNode> protectedLabels = new HashSet<>();
        if (method.tryCatchBlocks != null) {
            for (TryCatchBlockNode tcb : method.tryCatchBlocks) {
                protectedLabels.add(tcb.start);
                protectedLabels.add(tcb.end);
                protectedLabels.add(tcb.handler);
                markProtectedRange(tcb, executableIndexes, protectedExecutable);
            }
        }

        final boolean[] branchTargets = new boolean[executable.size()];
        collectBranchTargets(method, executableIndexes, branchTargets, protectedLabels);

        return new Analysis(method, frames, all, fullIndexes, executable, executableIndexes,
                protectedExecutable, branchTargets);
    }

    private void markProtectedRange(final TryCatchBlockNode tcb,
                                    final Map<AbstractInsnNode, Integer> executableIndexes,
                                    final boolean[] protectedExecutable) {
        boolean marking = false;
        for (AbstractInsnNode insn = tcb.start; insn != null; insn = insn.getNext()) {
            if (insn == tcb.start) {
                marking = true;
            }
            if (insn == tcb.end) {
                break;
            }
            if (marking && insn.getOpcode() >= 0) {
                final Integer index = executableIndexes.get(insn);
                if (index != null) {
                    protectedExecutable[index] = true;
                }
            }
        }
    }

    private void collectBranchTargets(final MethodNode method,
                                      final Map<AbstractInsnNode, Integer> executableIndexes,
                                      final boolean[] branchTargets,
                                      final Set<LabelNode> protectedLabels) {
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn instanceof JumpInsnNode) {
                markTarget(((JumpInsnNode) insn).label, executableIndexes, branchTargets);
            } else if (insn instanceof TableSwitchInsnNode) {
                final TableSwitchInsnNode table = (TableSwitchInsnNode) insn;
                markTarget(table.dflt, executableIndexes, branchTargets);
                for (LabelNode label : table.labels) {
                    markTarget(label, executableIndexes, branchTargets);
                }
            } else if (insn instanceof LookupSwitchInsnNode) {
                final LookupSwitchInsnNode lookup = (LookupSwitchInsnNode) insn;
                markTarget(lookup.dflt, executableIndexes, branchTargets);
                for (LabelNode label : lookup.labels) {
                    markTarget(label, executableIndexes, branchTargets);
                }
            }
        }

        for (LabelNode label : protectedLabels) {
            markTarget(label, executableIndexes, branchTargets);
        }
    }

    private void markTarget(final LabelNode label,
                            final Map<AbstractInsnNode, Integer> executableIndexes,
                            final boolean[] branchTargets) {
        if (label == null) {
            return;
        }
        for (AbstractInsnNode insn = label; insn != null; insn = insn.getNext()) {
            if (insn.getOpcode() < 0) {
                continue;
            }
            final Integer index = executableIndexes.get(insn);
            if (index != null) {
                branchTargets[index] = true;
            }
            return;
        }
    }

    private boolean isSafeRange(final Analysis analysis, final int start, final int end) {
        for (int i = start; i <= end; i++) {
            if (analysis.protectedExecutable[i] || analysis.branchTargets[i]) {
                return false;
            }
            if (!isSafeInstruction(analysis.executable.get(i))) {
                return false;
            }
        }
        return true;
    }

    private boolean isSafeInstruction(final AbstractInsnNode insn) {
        final int opcode = insn.getOpcode();
        if (insn instanceof JumpInsnNode || insn instanceof TableSwitchInsnNode || insn instanceof LookupSwitchInsnNode) {
            return false;
        }
        if (insn instanceof InvokeDynamicInsnNode) {
            return false;
        }
        if (insn instanceof MethodInsnNode && "<init>".equals(((MethodInsnNode) insn).name)) {
            return false;
        }
        if (insn instanceof LdcInsnNode) {
            final Object cst = ((LdcInsnNode) insn).cst;
            if (cst instanceof Handle || cst instanceof ConstantDynamic) {
                return false;
            }
        }
        if (opcode == Opcodes.NEW || opcode == Opcodes.MONITORENTER || opcode == Opcodes.MONITOREXIT) {
            return false;
        }
        if (opcode == Opcodes.ATHROW || opcode == Opcodes.RET
                || (opcode >= Opcodes.IRETURN && opcode <= Opcodes.RETURN)) {
            return false;
        }
        return !isComplexStackOpcode(opcode);
    }

    private boolean isComplexStackOpcode(final int opcode) {
        switch (opcode) {
            case Opcodes.POP:
            case Opcodes.POP2:
            case Opcodes.DUP:
            case Opcodes.DUP_X1:
            case Opcodes.DUP_X2:
            case Opcodes.DUP2:
            case Opcodes.DUP2_X1:
            case Opcodes.DUP2_X2:
            case Opcodes.SWAP:
                return true;
            default:
                return false;
        }
    }

    private Candidate buildCandidate(final Analysis analysis,
                                     final int startExec,
                                     final int endExec,
                                     final int maxInputs,
                                     final int maxOutputs,
                                     final int maxStackValues) {
        final AbstractInsnNode startInsn = analysis.executable.get(startExec);
        final AbstractInsnNode endInsn = analysis.executable.get(endExec);
        final Integer startFull = analysis.fullIndexes.get(startInsn);
        final Integer nextFull = nextFrameIndex(analysis, endInsn);
        if (startFull == null || nextFull == null) {
            return null;
        }

        final Frame<BasicValue> before = analysis.frames[startFull];
        final Frame<BasicValue> after = analysis.frames[nextFull];
        if (before == null || after == null) {
            return null;
        }
        if (before.getStackSize() > maxStackValues || after.getStackSize() > maxStackValues) {
            return null;
        }

        final LinkedHashSet<Integer> inputs = new LinkedHashSet<>();
        final LinkedHashSet<Integer> outputs = new LinkedHashSet<>();
        final LinkedHashSet<Integer> referenced = new LinkedHashSet<>();
        final Set<Integer> written = new HashSet<>();
        for (AbstractInsnNode insn = startInsn; insn != null; insn = insn.getNext()) {
            collectLocalUse(insn, inputs, outputs, referenced, written);
            if (insn == endInsn) {
                break;
            }
        }

        final List<ValueSpec> inputLocalTypes = localTypes(before, inputs);
        final List<ValueSpec> outputLocalTypes = localTypes(after, outputs);
        final List<ValueSpec> stackInputTypes = stackTypes(before);
        final List<ValueSpec> stackOutputTypes = stackTypes(after);
        if (inputLocalTypes == null || outputLocalTypes == null
                || stackInputTypes == null || stackOutputTypes == null) {
            return null;
        }
        if (hasAmbiguousReferenceType(inputLocalTypes)
                || hasAmbiguousReferenceType(outputLocalTypes)
                || hasAmbiguousReferenceType(stackInputTypes)
                || hasAmbiguousReferenceType(stackOutputTypes)) {
            return null;
        }
        if (inputLocalTypes.size() + stackInputTypes.size() > maxInputs) {
            return null;
        }
        if (outputLocalTypes.size() + stackOutputTypes.size() > maxOutputs) {
            return null;
        }

        final Candidate candidate = new Candidate();
        candidate.analysis = analysis;
        candidate.startInsn = startInsn;
        candidate.endInsn = endInsn;
        candidate.inputLocals = new ArrayList<>(inputs);
        candidate.outputLocals = new ArrayList<>(outputs);
        candidate.referencedLocals = new ArrayList<>(referenced);
        candidate.inputLocalTypes = inputLocalTypes;
        candidate.outputLocalTypes = outputLocalTypes;
        candidate.stackInputTypes = stackInputTypes;
        candidate.stackOutputTypes = stackOutputTypes;
        allocateHelperLocals(candidate);
        return candidate;
    }

    private Integer nextFrameIndex(final Analysis analysis, final AbstractInsnNode endInsn) {
        for (AbstractInsnNode next = endInsn.getNext(); next != null; next = next.getNext()) {
            final Integer index = analysis.fullIndexes.get(next);
            if (index != null && analysis.frames[index] != null) {
                return index;
            }
        }
        return null;
    }

    private void collectLocalUse(final AbstractInsnNode insn,
                                 final LinkedHashSet<Integer> inputs,
                                 final LinkedHashSet<Integer> outputs,
                                 final LinkedHashSet<Integer> referenced,
                                 final Set<Integer> written) {
        if (insn instanceof VarInsnNode) {
            final VarInsnNode varInsn = (VarInsnNode) insn;
            referenced.add(varInsn.var);
            if (isLoadOpcode(varInsn.getOpcode())) {
                if (!written.contains(varInsn.var)) {
                    inputs.add(varInsn.var);
                }
            } else if (isStoreOpcode(varInsn.getOpcode())) {
                outputs.add(varInsn.var);
                written.add(varInsn.var);
            }
        } else if (insn instanceof IincInsnNode) {
            final IincInsnNode iinc = (IincInsnNode) insn;
            referenced.add(iinc.var);
            if (!written.contains(iinc.var)) {
                inputs.add(iinc.var);
            }
            outputs.add(iinc.var);
            written.add(iinc.var);
        }
    }

    private List<ValueSpec> localTypes(final Frame<BasicValue> frame, final Iterable<Integer> locals) {
        final List<ValueSpec> specs = new ArrayList<>();
        for (Integer local : locals) {
            if (local == null || local < 0 || local >= frame.getLocals()) {
                return null;
            }
            final ValueSpec spec = toSpec(frame.getLocal(local));
            if (spec == null) {
                return null;
            }
            specs.add(spec);
        }
        return specs;
    }

    private List<ValueSpec> stackTypes(final Frame<BasicValue> frame) {
        final List<ValueSpec> specs = new ArrayList<>();
        for (int i = 0; i < frame.getStackSize(); i++) {
            final ValueSpec spec = toSpec(frame.getStack(i));
            if (spec == null) {
                return null;
            }
            specs.add(spec);
        }
        return specs;
    }

    private boolean hasAmbiguousReferenceType(final List<ValueSpec> specs) {
        for (ValueSpec spec : specs) {
            if (spec.type.getSort() == Type.OBJECT && OBJECT.equals(spec.type.getInternalName())) {
                return true;
            }
        }
        return false;
    }

    private ValueSpec toSpec(final BasicValue value) {
        if (value == null
                || value == BasicValue.UNINITIALIZED_VALUE
                || value == BasicValue.RETURNADDRESS_VALUE) {
            return null;
        }
        final Type type = value.getType();
        if (type == null) {
            return null;
        }
        switch (type.getSort()) {
            case Type.BOOLEAN:
            case Type.BYTE:
            case Type.CHAR:
            case Type.SHORT:
            case Type.INT:
                return new ValueSpec(Type.INT_TYPE);
            case Type.FLOAT:
                return new ValueSpec(Type.FLOAT_TYPE);
            case Type.LONG:
                return new ValueSpec(Type.LONG_TYPE);
            case Type.DOUBLE:
                return new ValueSpec(Type.DOUBLE_TYPE);
            case Type.ARRAY:
            case Type.OBJECT:
                return new ValueSpec(type);
            default:
                return null;
        }
    }

    private void allocateHelperLocals(final Candidate candidate) {
        final Map<Integer, ValueSpec> maxTypes = new LinkedHashMap<>();
        for (int i = 0; i < candidate.inputLocals.size(); i++) {
            mergeLocalType(maxTypes, candidate.inputLocals.get(i), candidate.inputLocalTypes.get(i));
        }
        for (int i = 0; i < candidate.outputLocals.size(); i++) {
            mergeLocalType(maxTypes, candidate.outputLocals.get(i), candidate.outputLocalTypes.get(i));
        }
        for (Integer local : candidate.referencedLocals) {
            if (!maxTypes.containsKey(local)) {
                maxTypes.put(local, new ValueSpec(Type.INT_TYPE));
            }
        }

        candidate.localMap = new HashMap<>();
        int next = 1;
        for (Integer local : candidate.referencedLocals) {
            final ValueSpec spec = maxTypes.get(local);
            candidate.localMap.put(local, next);
            next += spec == null ? 1 : spec.size;
        }
        candidate.helperLocalLimit = next;
    }

    private void mergeLocalType(final Map<Integer, ValueSpec> maxTypes, final Integer local, final ValueSpec spec) {
        final ValueSpec previous = maxTypes.get(local);
        if (previous == null || previous.size < spec.size) {
            maxTypes.put(local, spec);
        }
    }

    private MethodNode buildHelper(final Candidate candidate) {
        final MethodNode helper = new MethodNode(
                Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                candidate.helperName,
                OUTLINE_DESC,
                null,
                null
        );
        final InsnList out = helper.instructions;

        int inputIndex = 0;
        for (int i = 0; i < candidate.inputLocals.size(); i++) {
            final int originalLocal = candidate.inputLocals.get(i);
            final int helperLocal = candidate.localMap.get(originalLocal);
            final ValueSpec spec = candidate.inputLocalTypes.get(i);
            loadArrayElement(out, 0, inputIndex++);
            emitFromObject(out, spec.type);
            out.add(new VarInsnNode(spec.type.getOpcode(Opcodes.ISTORE), helperLocal));
        }

        for (ValueSpec spec : candidate.stackInputTypes) {
            loadArrayElement(out, 0, inputIndex++);
            emitFromObject(out, spec.type);
        }

        final Map<LabelNode, LabelNode> labels = new HashMap<>();
        for (AbstractInsnNode insn = candidate.startInsn; insn != null; insn = insn.getNext()) {
            if (insn instanceof LabelNode) {
                labels.put((LabelNode) insn, new LabelNode());
            }
            if (insn == candidate.endInsn) {
                break;
            }
        }

        for (AbstractInsnNode insn = candidate.startInsn; insn != null; insn = insn.getNext()) {
            if (!(insn instanceof FrameNode) && !(insn instanceof LineNumberNode) && insn.getOpcode() >= 0) {
                final AbstractInsnNode cloned = insn.clone(labels);
                remapLocal(cloned, candidate.localMap);
                skidfuscator.getDebugMappings().copied(insn, cloned);
                out.add(cloned);
            }
            if (insn == candidate.endInsn) {
                break;
            }
        }

        int nextLocal = candidate.helperLocalLimit;
        final int[] stackOutputLocals = new int[candidate.stackOutputTypes.size()];
        for (int i = candidate.stackOutputTypes.size() - 1; i >= 0; i--) {
            final ValueSpec spec = candidate.stackOutputTypes.get(i);
            final int local = nextLocal;
            nextLocal += spec.size;
            out.add(new VarInsnNode(spec.type.getOpcode(Opcodes.ISTORE), local));
            stackOutputLocals[i] = local;
        }

        final int outputArrayLocal = nextLocal++;
        pushInt(out, candidate.outputLocalTypes.size() + candidate.stackOutputTypes.size());
        out.add(new TypeInsnNode(Opcodes.ANEWARRAY, OBJECT));
        out.add(new VarInsnNode(Opcodes.ASTORE, outputArrayLocal));

        int outputIndex = 0;
        for (int i = 0; i < candidate.outputLocals.size(); i++) {
            final int originalLocal = candidate.outputLocals.get(i);
            final ValueSpec spec = candidate.outputLocalTypes.get(i);
            out.add(new VarInsnNode(Opcodes.ALOAD, outputArrayLocal));
            pushInt(out, outputIndex++);
            out.add(new VarInsnNode(spec.type.getOpcode(Opcodes.ILOAD), candidate.localMap.get(originalLocal)));
            emitToObject(out, spec.type);
            out.add(new InsnNode(Opcodes.AASTORE));
        }

        for (int i = 0; i < candidate.stackOutputTypes.size(); i++) {
            final ValueSpec spec = candidate.stackOutputTypes.get(i);
            out.add(new VarInsnNode(Opcodes.ALOAD, outputArrayLocal));
            pushInt(out, outputIndex++);
            out.add(new VarInsnNode(spec.type.getOpcode(Opcodes.ILOAD), stackOutputLocals[i]));
            emitToObject(out, spec.type);
            out.add(new InsnNode(Opcodes.AASTORE));
        }

        out.add(new VarInsnNode(Opcodes.ALOAD, outputArrayLocal));
        out.add(new InsnNode(Opcodes.ARETURN));
        helper.maxLocals = nextLocal;
        helper.maxStack = Math.max(12, candidate.stackInputTypes.size() + 8);
        return helper;
    }

    private void rewriteOriginal(final ClassNode classNode, final MethodNode method, final Candidate candidate) {
        method.maxLocals = Math.max(method.maxLocals, computeLocalLimit(method));
        nextScratchLocal = method.maxLocals;
        final InsnList replacement = new InsnList();

        final int[] stackInputLocals = new int[candidate.stackInputTypes.size()];
        for (int i = candidate.stackInputTypes.size() - 1; i >= 0; i--) {
            final ValueSpec spec = candidate.stackInputTypes.get(i);
            final int local = nextScratchLocal;
            nextScratchLocal += spec.size;
            replacement.add(new VarInsnNode(spec.type.getOpcode(Opcodes.ISTORE), local));
            stackInputLocals[i] = local;
        }

        final int inputArrayLocal = nextScratchLocal++;
        pushInt(replacement, candidate.inputLocalTypes.size() + candidate.stackInputTypes.size());
        replacement.add(new TypeInsnNode(Opcodes.ANEWARRAY, OBJECT));
        replacement.add(new VarInsnNode(Opcodes.ASTORE, inputArrayLocal));

        int inputIndex = 0;
        for (int i = 0; i < candidate.inputLocals.size(); i++) {
            final int originalLocal = candidate.inputLocals.get(i);
            final ValueSpec spec = candidate.inputLocalTypes.get(i);
            replacement.add(new VarInsnNode(Opcodes.ALOAD, inputArrayLocal));
            pushInt(replacement, inputIndex++);
            replacement.add(new VarInsnNode(spec.type.getOpcode(Opcodes.ILOAD), originalLocal));
            emitToObject(replacement, spec.type);
            replacement.add(new InsnNode(Opcodes.AASTORE));
        }
        for (int i = 0; i < candidate.stackInputTypes.size(); i++) {
            final ValueSpec spec = candidate.stackInputTypes.get(i);
            replacement.add(new VarInsnNode(Opcodes.ALOAD, inputArrayLocal));
            pushInt(replacement, inputIndex++);
            replacement.add(new VarInsnNode(spec.type.getOpcode(Opcodes.ILOAD), stackInputLocals[i]));
            emitToObject(replacement, spec.type);
            replacement.add(new InsnNode(Opcodes.AASTORE));
        }

        replacement.add(new VarInsnNode(Opcodes.ALOAD, inputArrayLocal));
        replacement.add(new MethodInsnNode(Opcodes.INVOKESTATIC, classNode.name,
                candidate.helperName, OUTLINE_DESC, false));

        final int outputArrayLocal = nextScratchLocal++;
        replacement.add(new VarInsnNode(Opcodes.ASTORE, outputArrayLocal));

        int outputIndex = 0;
        for (int i = 0; i < candidate.outputLocals.size(); i++) {
            final int originalLocal = candidate.outputLocals.get(i);
            final ValueSpec spec = candidate.outputLocalTypes.get(i);
            loadArrayElement(replacement, outputArrayLocal, outputIndex++);
            emitFromObject(replacement, spec.type);
            replacement.add(new VarInsnNode(spec.type.getOpcode(Opcodes.ISTORE), originalLocal));
        }
        for (ValueSpec spec : candidate.stackOutputTypes) {
            loadArrayElement(replacement, outputArrayLocal, outputIndex++);
            emitFromObject(replacement, spec.type);
        }

        method.instructions.insertBefore(candidate.startInsn, replacement);
        removeRange(method, candidate.startInsn, candidate.endInsn);
        method.maxLocals = Math.max(method.maxLocals, nextScratchLocal);
        method.maxStack = Math.max(method.maxStack, 16);
        method.localVariables = null;
        method.signature = null;
    }

    private void removeRange(final MethodNode method, final AbstractInsnNode start, final AbstractInsnNode end) {
        AbstractInsnNode cursor = start;
        while (cursor != null) {
            final AbstractInsnNode next = cursor.getNext();
            method.instructions.remove(cursor);
            if (cursor == end) {
                break;
            }
            cursor = next;
        }
    }

    private void remapLocal(final AbstractInsnNode insn, final Map<Integer, Integer> localMap) {
        if (insn instanceof VarInsnNode) {
            final VarInsnNode varInsn = (VarInsnNode) insn;
            final Integer mapped = localMap.get(varInsn.var);
            if (mapped != null) {
                varInsn.var = mapped;
            }
        } else if (insn instanceof IincInsnNode) {
            final IincInsnNode iinc = (IincInsnNode) insn;
            final Integer mapped = localMap.get(iinc.var);
            if (mapped != null) {
                iinc.var = mapped;
            }
        }
    }

    private int computeLocalLimit(final MethodNode method) {
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

    private int argumentLocalLimit(final MethodNode method) {
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

    private boolean isLoadOpcode(final int opcode) {
        return opcode >= Opcodes.ILOAD && opcode <= Opcodes.ALOAD;
    }

    private boolean isStoreOpcode(final int opcode) {
        return opcode >= Opcodes.ISTORE && opcode <= Opcodes.ASTORE;
    }

    private void loadArrayElement(final InsnList out, final int arrayLocal, final int index) {
        out.add(new VarInsnNode(Opcodes.ALOAD, arrayLocal));
        pushInt(out, index);
        out.add(new InsnNode(Opcodes.AALOAD));
    }

    private void emitToObject(final InsnList out, final Type type) {
        if (isPrimitive(type)) {
            emitBox(out, type);
        }
    }

    private void emitFromObject(final InsnList out, final Type type) {
        if (isPrimitive(type)) {
            final String wrapper = wrapperType(type);
            out.add(new TypeInsnNode(Opcodes.CHECKCAST, wrapper));
            out.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, wrapper,
                    unboxMethod(type), "()" + type.getDescriptor(), false));
        } else {
            emitCheckCast(out, type);
        }
    }

    private void emitBox(final InsnList out, final Type type) {
        final String wrapper = wrapperType(type);
        out.add(new MethodInsnNode(Opcodes.INVOKESTATIC, wrapper, "valueOf",
                "(" + type.getDescriptor() + ")L" + wrapper + ";", false));
    }

    private String wrapperType(final Type type) {
        switch (type.getSort()) {
            case Type.INT: return "java/lang/Integer";
            case Type.FLOAT: return "java/lang/Float";
            case Type.LONG: return "java/lang/Long";
            case Type.DOUBLE: return "java/lang/Double";
            default: throw new IllegalArgumentException("Not a primitive: " + type);
        }
    }

    private String unboxMethod(final Type type) {
        switch (type.getSort()) {
            case Type.INT: return "intValue";
            case Type.FLOAT: return "floatValue";
            case Type.LONG: return "longValue";
            case Type.DOUBLE: return "doubleValue";
            default: throw new IllegalArgumentException("Not a primitive: " + type);
        }
    }

    private void emitCheckCast(final InsnList out, final Type type) {
        if (type.getSort() == Type.OBJECT) {
            if (!OBJECT.equals(type.getInternalName())) {
                out.add(new TypeInsnNode(Opcodes.CHECKCAST, type.getInternalName()));
            }
        } else if (type.getSort() == Type.ARRAY) {
            out.add(new TypeInsnNode(Opcodes.CHECKCAST, type.getDescriptor()));
        }
    }

    private boolean isPrimitive(final Type type) {
        final int sort = type.getSort();
        return sort >= Type.BOOLEAN && sort <= Type.DOUBLE;
    }

    private void pushInt(final InsnList out, final int value) {
        if (value >= -1 && value <= 5) {
            out.add(new InsnNode(Opcodes.ICONST_0 + value));
        } else if (value >= Byte.MIN_VALUE && value <= Byte.MAX_VALUE) {
            out.add(new IntInsnNode(Opcodes.BIPUSH, value));
        } else if (value >= Short.MIN_VALUE && value <= Short.MAX_VALUE) {
            out.add(new IntInsnNode(Opcodes.SIPUSH, value));
        } else {
            out.add(new LdcInsnNode(value));
        }
    }

    private boolean isClassExempt(final org.mapleir.asm.ClassNode classNode) {
        return skidfuscator.getExemptAnalysis().isExempt(classNode)
                || skidfuscator.getExemptAnalysis().isExempt(getClass(), classNode);
    }

    private org.mapleir.asm.MethodNode findWrappedMethod(final org.mapleir.asm.ClassNode classNode,
                                                         final MethodNode method) {
        for (org.mapleir.asm.MethodNode candidate : classNode.getMethods()) {
            if (candidate.node == method) {
                return candidate;
            }
        }
        return null;
    }

    private String uniqueMethodName(final ClassNode classNode, final String prefix, final String desc) {
        String name;
        do {
            name = prefix + UUID.randomUUID().toString().replace("-", "");
        } while (hasMethod(classNode, name, desc));
        return name;
    }

    private boolean hasMethod(final ClassNode classNode, final String name, final String desc) {
        for (MethodNode method : classNode.methods) {
            if (method.name.equals(name) && method.desc.equals(desc)) {
                return true;
            }
        }
        return false;
    }

    private static final class Analysis {
        private final MethodNode method;
        private final Frame<BasicValue>[] frames;
        private final List<AbstractInsnNode> all;
        private final Map<AbstractInsnNode, Integer> fullIndexes;
        private final List<AbstractInsnNode> executable;
        private final Map<AbstractInsnNode, Integer> executableIndexes;
        private final boolean[] protectedExecutable;
        private final boolean[] branchTargets;

        private Analysis(final MethodNode method,
                         final Frame<BasicValue>[] frames,
                         final List<AbstractInsnNode> all,
                         final Map<AbstractInsnNode, Integer> fullIndexes,
                         final List<AbstractInsnNode> executable,
                         final Map<AbstractInsnNode, Integer> executableIndexes,
                         final boolean[] protectedExecutable,
                         final boolean[] branchTargets) {
            this.method = method;
            this.frames = frames;
            this.all = all;
            this.fullIndexes = fullIndexes;
            this.executable = executable;
            this.executableIndexes = executableIndexes;
            this.protectedExecutable = protectedExecutable;
            this.branchTargets = branchTargets;
        }
    }

    private static final class Candidate {
        private Analysis analysis;
        private AbstractInsnNode startInsn;
        private AbstractInsnNode endInsn;
        private List<Integer> inputLocals = Collections.emptyList();
        private List<Integer> outputLocals = Collections.emptyList();
        private List<Integer> referencedLocals = Collections.emptyList();
        private List<ValueSpec> inputLocalTypes = Collections.emptyList();
        private List<ValueSpec> outputLocalTypes = Collections.emptyList();
        private List<ValueSpec> stackInputTypes = Collections.emptyList();
        private List<ValueSpec> stackOutputTypes = Collections.emptyList();
        private Map<Integer, Integer> localMap = Collections.emptyMap();
        private int helperLocalLimit;
        private String helperName;
        private MethodNode helper;
    }

    private static final class ValueSpec {
        private final Type type;
        private final int size;

        private ValueSpec(final Type type) {
            this.type = type;
            this.size = type.getSize();
        }
    }
}
