package dev.skidfuscator.obfuscator.nativebackend;

import dev.skidfuscator.config.nativeobfuscation.NativeConfig;
import dev.skidfuscator.nativeir.*;
import dev.skidfuscator.obfuscator.nativebackend.commit.NativeMethodCommitTransaction;
import dev.skidfuscator.obfuscator.nativebackend.selection.NativeMethodMatcher;
import org.mapleir.asm.MethodNode;
import org.objectweb.asm.ConstantDynamic;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;

import java.util.*;
import java.util.function.Predicate;
import java.util.function.Function;

/** Computes Java entry liveness from the bodies that actually lowered, never requested coverage. */
final class NativeEntryPolicy {
    record Body(MethodNode method, NativeFunction function, NativeMethodCommitTransaction.Mutation mutation) {
        boolean copy() { return mutation instanceof NativeMethodCommitTransaction.JavaCopy; }
    }
    record Result(Set<String> liveCopies, Set<MethodNode> removed) { }

    static Result plan(NativeConfig config, List<Body> bodies, Collection<? extends MethodNode> methods,
                       Collection<JavaLinkageHelper> helpers, Predicate<MethodNode> contract) {
        Map<String, org.mapleir.asm.ClassNode> owners = new HashMap<>();
        methods.forEach(m -> owners.put(m.owner.getName(), m.owner));
        return plan(config, bodies, methods, helpers, contract, owners::get);
    }

    static Result plan(NativeConfig config, List<Body> bodies, Collection<? extends MethodNode> methods,
                       Collection<JavaLinkageHelper> helpers, Predicate<MethodNode> contract,
                       Function<String, org.mapleir.asm.ClassNode> resolver) {
        Map<String, Body> byName = new HashMap<>();
        bodies.forEach(b -> byName.put(key(b.function()), b));
        Set<String> reachable = new HashSet<>();
        Deque<Body> pending = new ArrayDeque<>();
        bodies.stream().filter(b -> !b.copy()).forEach(b -> { reachable.add(key(b.function())); pending.add(b); });
        while (!pending.isEmpty()) {
            Body caller = pending.remove();
            for (var call : calls(caller.function())) {
                Body target = byName.get(key(call));
                if (target != null && direct(caller.function(), target.function(), call)
                        && reachable.add(key(target.function()))) pending.add(target);
            }
        }
        Set<String> liveCopies = new HashSet<>();
        List<Body> live = new ArrayList<>();
        for (Body body : bodies) {
            if (!body.copy() || reachable.contains(key(body.function()))) live.add(body);
            if (body.copy() && reachable.contains(key(body.function()))) liveCopies.add(key(body.function()));
        }
        if (config.getPrunePrivateIncludes().isEmpty() && config.getPruneEntryIncludes().isEmpty())
            return new Result(liveCopies, Set.of());
        var includes = config.getPrunePrivateIncludes().stream().map(NativeMethodMatcher::compile).toList();
        var keeps = config.getPrunePrivateKeeps().stream().map(NativeMethodMatcher::compile).toList();
        var reviewedIncludes = config.getPruneEntryIncludes().stream().map(NativeMethodMatcher::compile).toList();
        var reviewedKeeps = config.getPruneEntryKeeps().stream().map(NativeMethodMatcher::compile).toList();
        Map<MethodNode, Body> converted = new IdentityHashMap<>();
        live.forEach(b -> converted.put(b.method(), b));
        Set<String> javaReferences = new HashSet<>(), handleReferences = new HashSet<>(), literals = new HashSet<>();
        // Read final Java bodies, including failed lowerings, copies, wrapper prefixes and generated linkage bridges.
        for (MethodNode method : methods) {
            Body body = converted.get(method);
            boolean retainsCode = body == null || body.copy();
            scan(method.node, retainsCode, javaReferences, handleReferences, literals);
            if (body != null && body.mutation() instanceof NativeMethodCommitTransaction.Wrapper wrapper)
                scan(wrapper.wrapperTemplate(), true, javaReferences, handleReferences, literals);
        }
        helpers.forEach(h -> scan(h.method(), true, javaReferences, handleReferences, literals));
        resolveReferences(javaReferences, resolver);
        resolveReferences(handleReferences, resolver);
        Set<String> needsDeclaration = new HashSet<>();
        for (Body caller : live) {
            for (var call : calls(caller.function())) {
                Body target = byName.get(key(call));
                // LLVM resolves exact owners. An inherited symbolic alias still needs JNI lookup.
                if (target == null) {
                    Set<String> aliases = new HashSet<>(Set.of(key(call)));
                    resolveReferences(aliases, resolver);
                    for (String alias : aliases) if (byName.containsKey(alias)) needsDeclaration.add(alias);
                }
                if (target != null && !direct(caller.function(), target.function(), call))
                    needsDeclaration.add(key(target.function()));
            }
        }
        Set<MethodNode> removed = Collections.newSetFromMap(new IdentityHashMap<>());
        for (Body body : live) {
            MethodNode method = body.method();
            String originalKey = method.owner.getName() + "#" + method.getName() + method.getDesc();
            boolean privateEntry = (method.node.access & Opcodes.ACC_PRIVATE) != 0;
            boolean reviewed = reviewedIncludes.stream().anyMatch(m -> m.matches(method));
            if (!(body.mutation() instanceof NativeMethodCommitTransaction.Direct)
                    || body.function().backend() != NativeBackend.AOT || body.function().synchronizedMethod()
                    || (!privateEntry && !reviewed) || method.getName().startsWith("<")
                    || annotated(method.node) || contract.test(method) || serializationHook(method.getName())
                    || (!reviewed && includes.stream().noneMatch(m -> m.matches(method)))
                    || keeps.stream().anyMatch(m -> m.matches(method)) || reviewedKeeps.stream().anyMatch(m -> m.matches(method))
                    || (!privateEntry && hierarchyContract(method, methods, resolver))
                    || javaReferences.contains(originalKey) || javaReferences.contains(key(body.function()))
                    || handleReferences.contains(originalKey) || handleReferences.contains(key(body.function()))
                    || literals.contains(method.getName()) || literals.contains(body.function().javaName())
                    || needsDeclaration.contains(key(body.function()))) continue;
            removed.add(method);
        }
        return new Result(Set.copyOf(liveCopies), Collections.unmodifiableSet(removed));
    }

    /** Resolve inherited symbolic owners so surviving bytecode cannot lose its declaration. */
    private static void resolveReferences(Set<String> references, Function<String, org.mapleir.asm.ClassNode> resolver) {
        for (String ref : List.copyOf(references)) {
            int separator = ref.indexOf('#'), descriptor = ref.indexOf('(', separator);
            if (separator < 0 || descriptor < 0) continue;
            String signature = ref.substring(separator + 1);
            Deque<String> pending = new ArrayDeque<>(List.of(ref.substring(0, separator)));
            Set<String> seen = new HashSet<>();
            while (!pending.isEmpty()) {
                String owner = pending.remove();
                if (!seen.add(owner)) continue;
                var node = resolver.apply(owner);
                if (node == null) continue;
                if (node.node.methods.stream().anyMatch(m -> (m.name + m.desc).equals(signature))) {
                    references.add(owner + "#" + signature);
                    continue;
                }
                if (node.node.superName != null) pending.add(node.node.superName);
                pending.addAll(node.node.interfaces);
            }
        }
    }

    /** Instance override families keep their Java declarations, including external runtime contracts. */
    private static boolean hierarchyContract(MethodNode method, Collection<? extends MethodNode> methods,
                                             Function<String, org.mapleir.asm.ClassNode> resolver) {
        if ((method.node.access & Opcodes.ACC_STATIC) != 0) return false;
        Deque<String> pending = new ArrayDeque<>();
        if (method.owner.node.superName != null) pending.add(method.owner.node.superName);
        pending.addAll(method.owner.node.interfaces);
        Set<String> seen = new HashSet<>();
        while (!pending.isEmpty()) {
            String owner = pending.remove();
            if (!seen.add(owner)) continue;
            var node = resolver.apply(owner);
            if (node == null) return true; // An unresolved ancestor is not proof of a closed contract.
            if (node.node.methods.stream().anyMatch(m -> m.name.equals(method.getName())
                    && m.desc.equals(method.getDesc()) && (m.access & (Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC)) == 0))
                return true;
            if (node.node.superName != null) pending.add(node.node.superName);
            pending.addAll(node.node.interfaces);
        }
        for (MethodNode other : methods) {
            if (other.owner == method.owner || !other.getName().equals(method.getName())
                    || !other.getDesc().equals(method.getDesc())
                    || (other.node.access & (Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC)) != 0) continue;
            pending.add(other.owner.getName());
            seen.clear();
            while (!pending.isEmpty()) {
                String owner = pending.remove();
                if (!seen.add(owner)) continue;
                if (owner.equals(method.owner.getName())) return true;
                var node = resolver.apply(owner);
                if (node == null) continue;
                if (node.node.superName != null) pending.add(node.node.superName);
                pending.addAll(node.node.interfaces);
            }
        }
        return false;
    }

    private static boolean serializationHook(String name) {
        return Set.of("readObject", "writeObject", "readObjectNoData", "readResolve", "writeReplace", "$deserializeLambda$").contains(name);
    }

    private static boolean annotated(org.objectweb.asm.tree.MethodNode method) {
        return method.visibleAnnotations != null && !method.visibleAnnotations.isEmpty()
                || method.invisibleAnnotations != null && !method.invisibleAnnotations.isEmpty();
    }

    private static void scan(org.objectweb.asm.tree.MethodNode method, boolean retainsCode, Set<String> refs,
                             Set<String> handles, Set<String> literals) {
        for (var insn : method.instructions) {
            if (retainsCode && insn instanceof MethodInsnNode call) refs.add(call.owner + "#" + call.name + call.desc);
            if (insn instanceof LdcInsnNode ldc) constant(ldc.cst, handles, literals);
            if (insn instanceof InvokeDynamicInsnNode indy) {
                constant(indy.bsm, handles, literals);
                for (Object value : indy.bsmArgs) constant(value, handles, literals);
            }
        }
    }

    private static void constant(Object value, Set<String> handles, Set<String> literals) {
        if (value instanceof String text) literals.add(text);
        else if (value instanceof Handle handle) handles.add(handle.getOwner() + "#" + handle.getName() + handle.getDesc());
        else if (value instanceof ConstantDynamic dynamic) {
            constant(dynamic.getBootstrapMethod(), handles, literals);
            for (int i = 0; i < dynamic.getBootstrapMethodArgumentCount(); i++) constant(dynamic.getBootstrapMethodArgument(i), handles, literals);
        }
    }

    static List<NativeInstruction.Operation> calls(NativeFunction function) {
        return function.blocks().stream().flatMap(b -> b.instructions().stream())
                .filter(NativeInstruction.Operation.class::isInstance).map(NativeInstruction.Operation.class::cast)
                .filter(op -> op.opcode() == NativeOpcode.JAVA_CALL).toList();
    }

    static boolean direct(NativeFunction caller, NativeFunction target, NativeInstruction.Operation call) {
        if (caller.backend() != NativeBackend.AOT || target.backend() != NativeBackend.AOT
                || target.synchronizedMethod() || target.javaName().startsWith("<")) return false;
        String invoke = call.attributes().get("invoke");
        if (flag(target, "java.static")) return "static".equals(invoke);
        return "special".equals(invoke) && flag(target, "java.private") && caller.javaOwner().equals(target.javaOwner())
                || "virtual".equals(invoke) && (flag(target, "java.final") || flag(target, "java.classFinal"));
    }

    private static boolean flag(NativeFunction function, String name) { return "true".equals(function.metadata().get(name)); }
    static String key(NativeFunction f) { return f.javaOwner() + "#" + f.javaName() + f.javaDescriptor(); }
    private static String key(NativeInstruction.Operation call) {
        return call.attributes().get("owner") + "#" + call.attributes().get("name") + call.attributes().get("descriptor");
    }

    static NativeFunction withEntry(NativeFunction function, String entry) {
        Map<String, String> metadata = new HashMap<>(function.metadata());
        metadata.put("java.entry", entry);
        if ("removed".equals(entry)) metadata.put("java.entryCalls", "cross-class-v1");
        if ("removed".equals(entry) && !flag(function, "java.private"))
            metadata.put("java.entryScope", "closed-world-v1");
        NativeFunction copy = new NativeFunction(function.symbol(), function.javaOwner(), function.javaName(),
                function.javaDescriptor(), function.returnType(), function.parameters(), function.entryBlock(),
                function.backend(), function.synchronizedMethod(), function.requiresSemanticContext(), metadata);
        function.blocks().forEach(copy::addBlock);
        return copy;
    }
}
