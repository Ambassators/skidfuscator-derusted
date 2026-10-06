package dev.skidfuscator.obfuscator.nativebackend;

import dev.skidfuscator.config.nativeobfuscation.NativeConfig;
import dev.skidfuscator.config.nativeobfuscation.NativeMode;
import dev.skidfuscator.obfuscator.nativebackend.selection.NativeMethodMatcher;
import dev.skidfuscator.obfuscator.nativebackend.selection.NativeSelection;
import dev.skidfuscator.obfuscator.nativebackend.selection.NativeSelectionSource;
import org.mapleir.asm.MethodNode;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.MethodInsnNode;

import java.util.*;

/** Reserve reachable Java copies before structural transforms can change their ABI. */
final class NativeJavaCopyPlanner {
    static void reserve(NativeConfig config, Collection<? extends MethodNode> methods,
                        List<NativeCompilationPlan.Candidate> candidates) {
        if (!config.isEnabled() || config.getJavaCopyIncludes().isEmpty()) return;
        List<NativeMethodMatcher> includes = config.getJavaCopyIncludes().stream().map(NativeMethodMatcher::compile).toList();
        List<NativeMethodMatcher> excludes = config.getJavaCopyExemptions().stream().map(NativeMethodMatcher::compile).toList();
        Map<String, MethodNode> byName = new HashMap<>();
        methods.forEach(m -> byName.put(key(m), m));
        Set<MethodNode> selected = Collections.newSetFromMap(new IdentityHashMap<>());
        Deque<MethodNode> pending = new ArrayDeque<>();
        for (var candidate : candidates) {
            selected.add(candidate.selection().getMethod());
            if (candidate.selection().getMode() == NativeMode.AOT) pending.add(candidate.selection().getMethod());
        }
        while (!pending.isEmpty()) {
            MethodNode caller = pending.remove();
            for (var insn : caller.node.instructions) {
                if (!(insn instanceof MethodInsnNode call)) continue;
                MethodNode target = byName.get(call.owner + "#" + call.name + call.desc);
                if (target == null || selected.contains(target) || !direct(caller, target, call.getOpcode())
                        || includes.stream().noneMatch(m -> m.matches(target))
                        || excludes.stream().anyMatch(m -> m.matches(target))
                        || NativeEligibility.check(target).conversion() != NativeEligibility.Conversion.DIRECT) continue;
                candidates.add(new NativeCompilationPlan.Candidate(new NativeSelection(target, NativeMode.AOT,
                        NativeSelectionSource.JAVA_COPY, false), NativeEligibility.Conversion.DIRECT));
                selected.add(target);
                pending.add(target);
            }
        }
    }

    private static boolean direct(MethodNode caller, MethodNode target, int opcode) {
        int flags = target.node.access;
        if (target.getName().startsWith("<") || (flags & Opcodes.ACC_SYNCHRONIZED) != 0) return false;
        if (target.isStatic()) return opcode == Opcodes.INVOKESTATIC;
        return opcode == Opcodes.INVOKESPECIAL && (flags & Opcodes.ACC_PRIVATE) != 0 && caller.owner == target.owner
                || opcode == Opcodes.INVOKEVIRTUAL && ((flags | target.owner.node.access) & Opcodes.ACC_FINAL) != 0;
    }

    private static String key(MethodNode method) {
        return method.owner.getName() + "#" + method.getName() + method.getDesc();
    }
}
