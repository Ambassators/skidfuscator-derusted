package dev.skidfuscator.obfuscator.nativebackend;

import com.typesafe.config.ConfigFactory;
import dev.skidfuscator.config.nativeobfuscation.NativeConfig;
import dev.skidfuscator.nativeir.*;
import dev.skidfuscator.obfuscator.nativebackend.commit.NativeMethodCommitTransaction;
import dev.skidfuscator.obfuscator.nativebackend.selection.NativeSelectionSource;
import org.junit.jupiter.api.Test;
import org.mapleir.asm.ClassNode;
import org.mapleir.asm.MethodNode;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

class NativeEntryPolicyTest implements Opcodes {
    private final ClassNode owner = owner("example/Owner");
    private final NativeConfig config = config("native.prunePrivate.include=[\"class{.*}\"]");

    @Test void reservesOnlyReachableCopiesAndRetainsExemptionMeaning() {
        MethodNode root = method(owner, "root", ACC_PUBLIC | ACC_STATIC);
        MethodNode copy = method(owner, "copy", ACC_PUBLIC | ACC_STATIC);
        MethodNode transitive = method(owner, "transitive", ACC_PRIVATE | ACC_STATIC);
        MethodNode unused = method(owner, "unused", ACC_PUBLIC | ACC_STATIC);
        MethodNode sync = method(owner, "sync", ACC_PUBLIC | ACC_STATIC | ACC_SYNCHRONIZED);
        MethodNode excluded = method(owner, "excluded", ACC_PUBLIC | ACC_STATIC);
        invoke(root, copy); invoke(copy, transitive); invoke(copy, copy); invoke(root, sync); invoke(root, excluded);
        var settings = config("""
                native.enabled=true
                native.include=["method{root}"]
                native.exempt=["method{copy|transitive|unused|sync|excluded}"]
                native.javaCopies.include=["class{.*}"]
                native.javaCopies.exempt=["method{excluded}"]
                """);
        var plan = new NativeCompilationPlanner(settings).plan(owner.getMethods());
        assertEquals(Set.of(root, copy, transitive), new HashSet<>(plan.candidates().stream().map(c -> c.selection().getMethod()).toList()));
        assertEquals(2, plan.candidates().stream().filter(c -> c.selection().getSource() == NativeSelectionSource.JAVA_COPY).count());
        assertEquals(1, new NativeCompilationPlanner(config("native.enabled=true\nnative.include=[\"method{root}\"]"))
                .plan(owner.getMethods()).candidates().size());
    }

    @Test void removesNativeOnlyPrivateRecursion() {
        MethodNode root = method(owner, "root", ACC_PUBLIC | ACC_STATIC);
        MethodNode helper = method(owner, "helper", ACC_PRIVATE | ACC_STATIC);
        invoke(root, helper); invoke(helper, helper);
        var result = plan(List.of(body(root, false, helper), body(helper, false, helper)));
        assertEquals(Set.of(helper), result.removed());
    }

    @Test void keepsEntryNeededByJavaCopyAndByFailedLowering() {
        MethodNode copy = method(owner, "copy", ACC_PUBLIC | ACC_STATIC);
        MethodNode helper = method(owner, "helper", ACC_PRIVATE | ACC_STATIC);
        MethodNode root = method(owner, "root", ACC_PUBLIC | ACC_STATIC);
        invoke(copy, helper);
        assertTrue(plan(List.of(body(root, false, copy), body(copy, true, helper), body(helper, false))).removed().isEmpty());
        // A selected method whose lowering failed is absent from the compiled bodies.
        assertTrue(plan(List.of(body(root, false), body(helper, false))).removed().isEmpty());
    }

    @Test void discardsCopiesDisconnectedByLoweringFailure() {
        MethodNode root = method(owner, "root", ACC_PUBLIC | ACC_STATIC);
        MethodNode a = method(owner, "a", ACC_PUBLIC | ACC_STATIC);
        MethodNode b = method(owner, "b", ACC_PRIVATE | ACC_STATIC);
        var result = plan(List.of(body(root, false), body(a, true, b), body(b, true, a)));
        assertTrue(result.liveCopies().isEmpty());
    }

    @Test void removesCrossOwnerCallsWithDeclarationIndependentClassInitialization() {
        MethodNode root = method(owner("example/Other"), "root", ACC_PUBLIC | ACC_STATIC);
        MethodNode helper = method(owner, "helper", ACC_PRIVATE | ACC_STATIC);
        assertEquals(Set.of(helper), plan(List.of(body(root, false, helper), body(helper, false))).removed());
    }

    @Test void keepsAnnotationsSynchronizationHandlesReflectionAndContracts() {
        MethodNode root = method(owner, "root", ACC_PUBLIC | ACC_STATIC);
        MethodNode annotation = method(owner, "annotation", ACC_PRIVATE | ACC_STATIC);
        annotation.node.visibleAnnotations = new ArrayList<>(List.of(new AnnotationNode("Lexample/Event;")));
        MethodNode sync = method(owner, "sync", ACC_PRIVATE | ACC_STATIC | ACC_SYNCHRONIZED);
        MethodNode handle = method(owner, "handle", ACC_PRIVATE | ACC_STATIC);
        root.node.instructions.insert(new LdcInsnNode(new Handle(H_INVOKESTATIC, owner.getName(), "handle", "()V", false)));
        MethodNode reflection = method(owner, "reflection", ACC_PRIVATE | ACC_STATIC);
        root.node.instructions.insert(new LdcInsnNode("reflection"));
        MethodNode contract = method(owner, "contract", ACC_PRIVATE | ACC_STATIC);
        List<NativeEntryPolicy.Body> bodies = List.of(body(root, false), body(annotation, false), body(sync, false),
                body(handle, false), body(reflection, false), body(contract, false));
        assertTrue(NativeEntryPolicy.plan(config, bodies, owner.getMethods(), List.of(), m -> m == contract).removed().isEmpty());
    }

    @Test void keepsLambdaHandleEvenWhenItsOriginalCallerIsNative() {
        MethodNode root = method(owner, "root", ACC_PUBLIC | ACC_STATIC);
        MethodNode lambda = method(owner, "lambda", ACC_PRIVATE | ACC_STATIC);
        root.node.instructions.insert(new InvokeDynamicInsnNode("run", "()Ljava/lang/Runnable;",
                new Handle(H_INVOKESTATIC, "example/Bootstrap", "boot", "()V", false),
                new Handle(H_INVOKESTATIC, owner.getName(), "lambda", "()V", false)));
        assertTrue(plan(List.of(body(root, false), body(lambda, false))).removed().isEmpty());
    }

    @Test void scansGeneratedJavaLinkageHelpers() {
        MethodNode target = method(owner, "target", ACC_PRIVATE | ACC_STATIC);
        var raw = new org.objectweb.asm.tree.MethodNode(ACC_STATIC | ACC_SYNTHETIC, "bridge", "()V", null, null);
        raw.instructions.add(new MethodInsnNode(INVOKESTATIC, owner.getName(), "target", "()V", false));
        assertTrue(NativeEntryPolicy.plan(config, List.of(body(target, false)), owner.getMethods(),
                List.of(new JavaLinkageHelper(owner, raw, "test")), m -> false).removed().isEmpty());
    }

    private NativeEntryPolicy.Result plan(List<NativeEntryPolicy.Body> bodies) {
        return NativeEntryPolicy.plan(config, bodies, owner.getMethods(), List.of(), m -> false);
    }
    private static NativeConfig config(String text) { return new NativeConfig(ConfigFactory.parseString(text), "native"); }
    private static ClassNode owner(String name) {
        ClassNode result = new ClassNode(); result.node.name = name; result.node.superName = "java/lang/Object"; return result;
    }
    private static MethodNode method(ClassNode owner, String name, int flags) {
        var raw = new org.objectweb.asm.tree.MethodNode(flags, name, "()V", null, null);
        raw.instructions.add(new InsnNode(RETURN));
        MethodNode result = new MethodNode(raw, owner); owner.addMethod(result); return result;
    }
    private static void invoke(MethodNode caller, MethodNode target) {
        caller.node.instructions.insert(new MethodInsnNode(INVOKESTATIC, target.owner.getName(), target.getName(), target.getDesc(), false));
    }
    private static NativeEntryPolicy.Body body(MethodNode method, boolean copy, MethodNode... callees) {
        NativeBlock block = new NativeBlock("entry");
        int index = 0;
        for (MethodNode target : callees) block.addInstruction(new NativeInstruction.Operation("call" + index++,
                NativeType.Primitive.VOID, NativeOpcode.JAVA_CALL, List.of(), Map.of("owner", target.owner.getName(),
                "name", target.getName(), "descriptor", target.getDesc(), "invoke", "static"), SourceLocation.UNKNOWN));
        NativeFunction function = new NativeFunction("fn_" + method.getName(), method.owner.getName(), method.getName(),
                method.getDesc(), NativeType.Primitive.VOID, List.of(), "entry", NativeBackend.AOT,
                (method.node.access & ACC_SYNCHRONIZED) != 0, Map.of("java.static", "true", "java.private",
                Boolean.toString((method.node.access & ACC_PRIVATE) != 0))).addBlock(block);
        return new NativeEntryPolicy.Body(method, function, copy ? new NativeMethodCommitTransaction.JavaCopy(method)
                : new NativeMethodCommitTransaction.Direct(method));
    }
}
