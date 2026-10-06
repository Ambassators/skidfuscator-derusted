package dev.skidfuscator.obfuscator.transform.impl.flow.interprocedural;

import dev.skidfuscator.obfuscator.Skidfuscator;
import dev.skidfuscator.obfuscator.event.annotation.Listen;
import dev.skidfuscator.obfuscator.event.impl.transform.clazz.InitClassTransformEvent;
import dev.skidfuscator.obfuscator.event.impl.transform.group.InitGroupTransformEvent;
import dev.skidfuscator.obfuscator.event.impl.transform.method.InitMethodTransformEvent;
import dev.skidfuscator.obfuscator.hierarchy.matching.ClassMethodHash;
import dev.skidfuscator.obfuscator.number.NumberManager;
import dev.skidfuscator.obfuscator.predicate.factory.PredicateFlowGetter;
import dev.skidfuscator.obfuscator.predicate.factory.PredicateFlowSetter;
import dev.skidfuscator.obfuscator.predicate.opaque.BlockOpaquePredicate;
import dev.skidfuscator.obfuscator.predicate.opaque.ClassOpaquePredicate;
import dev.skidfuscator.obfuscator.predicate.opaque.MethodOpaquePredicate;
import dev.skidfuscator.obfuscator.skidasm.*;
import dev.skidfuscator.obfuscator.skidasm.cfg.SkidBlock;
import dev.skidfuscator.obfuscator.skidasm.expr.SkidConstantExpr;
import dev.skidfuscator.obfuscator.skidasm.expr.SkidIntegerParseStaticInvocationExpr;
import dev.skidfuscator.obfuscator.skidasm.stmt.SkidCopyVarStmt;
import dev.skidfuscator.obfuscator.transform.AbstractTransformer;
import dev.skidfuscator.obfuscator.transform.impl.flow.FlowFactoryMakerTransformer;
import dev.skidfuscator.obfuscator.util.OpcodeUtil;
import dev.skidfuscator.obfuscator.util.RandomUtil;
import dev.skidfuscator.obfuscator.util.misc.Parameter;
import org.mapleir.asm.MethodNode;
import org.mapleir.ir.cfg.BasicBlock;
import org.mapleir.ir.cfg.ControlFlowGraph;
import org.mapleir.ir.code.Expr;
import org.mapleir.ir.code.Stmt;
import org.mapleir.ir.code.expr.ArithmeticExpr;
import org.mapleir.ir.code.expr.CastExpr;
import org.mapleir.ir.code.expr.ConstantExpr;
import org.mapleir.ir.code.expr.FieldLoadExpr;
import org.mapleir.ir.code.expr.VarExpr;
import org.mapleir.ir.code.expr.invoke.DynamicInvocationExpr;
import org.mapleir.ir.code.expr.invoke.InitialisedObjectExpr;
import org.mapleir.ir.code.expr.invoke.InvocationExpr;
import org.mapleir.ir.code.expr.invoke.VirtualInvocationExpr;
import org.mapleir.ir.code.stmt.FieldStoreStmt;
import org.mapleir.ir.locals.Local;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import java.util.stream.Collectors;

public class InterproceduralTransformer extends AbstractTransformer {
    public InterproceduralTransformer(final Skidfuscator skidfuscator) {
        super(skidfuscator, "Interprocedural");
    }

    @Listen
    void handle(final InitGroupTransformEvent event) {
        final SkidGroup skidGroup = event.getGroup();
        final boolean wide = skidfuscator.getConfig().isSeedWide();

        /*
         * This can occur. Warn the user then skip. No significant damage
         * should be caused by skipping this method.
         *
         * TODO: Add stricter exception logging for this
         */
        if (skidGroup.getPredicate().getGetter() != null) {
            System.err.println("SkidGroup " + skidGroup.getName() + " does not have getter!");
            return;
        }

        final boolean entryPoint = skidGroup.isEntryPoint();
        int stackHeight = -1;

        /*
         * Do not thread constructors, compiler-synthetic helper methods, or
         * methods declared in/called from anonymous or inner classes.
         * Updating constructor descriptors is fragile because allocation sites
         * are split across NEW/DUP/.../INVOKESPECIAL and some constructor calls
         * or classes can be skipped by later bytecode-level passes. Synthetic
         * accessors are similarly fragile because anonymous/nested classes may
         * keep direct references to their compiler-generated descriptors. Inner
         * and anonymous classes also often extend or implement library classes,
         * so descriptor threading can break override/callback signatures.
         * A caller/callee descriptor mismatch produces runtime NoSuchMethodError,
         * e.g. Foo$1.<init>(Foo, int) or Foo.access$008(Foo).
         */
        if (skidGroup.isInit()
                || skidGroup.isClinit()
                || skidGroup.isSynthetic()
                || hasFragileMethodOwner(skidGroup)
                || hasFragileInvokerOwner(skidGroup)) {
            stackHeight = OpcodeUtil.getArgumentsSizes(skidGroup.getDesc());

            if (skidGroup.isStatical())
                stackHeight -= 1;

            skidGroup.setStackHeight(stackHeight);
            return;
        }

        /*
         * If the skid group is an entry point (it has no direct invocation)
         * or in the future when we support reflection calls
         */
        if (entryPoint || (skidGroup.isStatical() && !threadStaticMethods())) {
            stackHeight = OpcodeUtil.getArgumentsSizes(skidGroup.getDesc());

            if (skidGroup.isStatical())
                stackHeight -= 1;

            skidGroup.setStackHeight(stackHeight);
            return;
        }

        Local local = null;
        String desc = null;

        int indexGroup = -1;

        //System.out.println("Iterating group " + skidGroup.getName());

        final Parameter parameterGroup = new Parameter(skidGroup.getDesc());
        if (skidGroup.getInvokers().stream().map(SkidInvocation::getExpr)
                .anyMatch(DynamicInvocationExpr.class::isInstance)) {
            final DynamicInvocationExpr invocationExpr = skidGroup
                    .getInvokers()
                    .stream()
                    .map(SkidInvocation::getExpr)
                    .filter(DynamicInvocationExpr.class::isInstance)
                    .findFirst()
                    .map(DynamicInvocationExpr.class::cast)
                    .orElseThrow(IllegalStateException::new);

            final Parameter bootstrappedParam = new Parameter(
                    invocationExpr.getDesc()
            );
            indexGroup = bootstrappedParam.getArgs().size();
        } else {
            indexGroup = parameterGroup.getArgs().size();
        }

        parameterGroup.insertParameter(wide ? Type.LONG_TYPE : Type.INT_TYPE, indexGroup);

        for (MethodNode methodNode : skidGroup.getMethodNodeList()) {
            final SkidMethodNode skidMethodNode = (SkidMethodNode) methodNode;

            stackHeight = parameterGroup.computeSize(indexGroup);
            if (!methodNode.isStatic()) stackHeight += 1;

            final Map<String, Local> localMap = new HashMap<>();
            for (Map.Entry<String, Local> stringLocalEntry :
                    skidMethodNode.getCfg().getLocals().getCache().entrySet()) {
                final String old = stringLocalEntry.getKey();
                final String oldStringId = old.split("var")[1].split("_")[0];
                final int oldId = Integer.parseInt(oldStringId);

                if (oldId < stackHeight) {
                    localMap.put(old, stringLocalEntry.getValue());
                    continue;
                }
                // A long seed parameter occupies two local slots, so everything at
                // or above the insertion point must shift by 2 (not 1) under wide.
                final int slots = wide ? 2 : 1;
                final int newId = oldId + slots;

                final String newVar = old.replace("var" + oldStringId, "var" + Integer.toString(newId));
                stringLocalEntry.getValue().setIndex(stringLocalEntry.getValue().getIndex() + slots);
                localMap.put(newVar, stringLocalEntry.getValue());
            }

            skidMethodNode.getCfg().getLocals().getCache().clear();
            skidMethodNode.getCfg().getLocals().getCache().putAll(localMap);

            if ((methodNode.node.access & Opcodes.ACC_VARARGS) != 0) {
                methodNode.node.access &= ~Opcodes.ACC_VARARGS;
            }

            final ClassMethodHash classMethodHash = new ClassMethodHash(
                    skidMethodNode.getName(),
                    parameterGroup.getDesc(),
                    skidMethodNode.getOwner()
            );

            //System.out.println("Group: " + skidGroup.getName() + " Method: " + skidMethodNode.getName() + " Desc: " + parameterGroup.getDesc());
            //System.out.println(skidfuscator.getHierarchy().getGroups().stream().map(SkidGroup::toString).collect(Collectors.joining("\n")));
            if (skidfuscator.getHierarchy().getGroup(classMethodHash) != null && !skidGroup.getName().contains("<")) {
                //System.out.println("FOUND! Group: " + skidGroup.getName() + " Method: " + skidMethodNode.getName() + " Desc: " + parameterGroup.getDesc());
                skidGroup.setName(skidGroup.getName() + "$" + RandomUtil.nextInt());
            }

            if (local == null) {
                local = skidMethodNode.getCfg().getLocals().get(stackHeight);
            }
        }

        if (!skidGroup.getInvokers().isEmpty()) {
            for (SkidInvocation invoker : skidGroup.getInvokers()) {
                assert invoker != null : String.format("Invoker %s is null!", Arrays.toString(skidGroup.getInvokers().toArray()));

                if (invoker.getExpr() == null) {
                    Skidfuscator.LOGGER.warn(
                            "Skipping non-IR invoker for "
                                    + skidGroup.getName()
                                    + skidGroup.getDesc()
                                    + " from "
                                    + invoker.getOwner().getDisplayName()
                    );
                    continue;
                }

                if (invoker.isTainted()) {
                    Skidfuscator.LOGGER.warn("Warning! Almost duplicated call on " + invoker.getExpr());
                    continue;
                }

                //if (skidGroup.getName().equals("getConfig"))
                //    System.out.println("Replacing invoker " + invoker.asExpr().getOwner() + "#" + invoker.asExpr().getName() + invoker.asExpr().getDesc() + " in " + invoker.getOwner().toString());
                final boolean isDynamic = invoker.getExpr() instanceof DynamicInvocationExpr;

                int index = 0;
                final Expr[] params = /*isDynamic
                    ? ((DynamicInvocationExpr) invoker.getExpr()).getPrintedArgs()
                    : */invoker.getExpr().getArgumentExprs();
                for (Expr argumentExpr : params) {
                    assert argumentExpr != null : "Argument of index " + index + " is null!";
                    index++;
                }

                final Expr[] args = new Expr[params.length + 1];
                System.arraycopy(
                        params,
                        0,
                        args,
                        0,
                        params.length
                );

                /*
                 * The seed argument must be a SkidConstantExpr (not a plain
                 * ConstantExpr) so the NumberTransformer's PostMethod pass picks
                 * it up and rewrites it into a flow-seed-dependent expression
                 * (n ^ C). A plain ConstantExpr is skipped and leaks the raw
                 * public seed at the call site, defeating the obfuscation.
                 */
                args[args.length - 1] = new SkidConstantExpr(
                        wide
                                ? (Object) skidGroup.getPredicate().getPublicLong()
                                : (Object) skidGroup.getPredicate().getPublic()
                );

                for (Expr arg : args) {
                    assert arg != null : "Invocation now is null? " + invoker.asExpr();
                }

                invoker.getExpr().setArgumentExprs(args);
                //System.out.println(invoker.asExpr());
                invoker.setTainted(true);

                if (isDynamic) {
                    final Handle boundFunc = (Handle) ((DynamicInvocationExpr) invoker.getExpr()).getBootstrapArgs()[1];
                    final Parameter handlerDesc = new Parameter(boundFunc.getDesc());
                    handlerDesc.insertParameter(wide ? Type.LONG_TYPE : Type.INT_TYPE, indexGroup);
                    final Handle newBoundFunc = new Handle(boundFunc.getTag(), boundFunc.getOwner(), boundFunc.getName(),
                            handlerDesc.getDesc(), boundFunc.isInterface());

                    final Parameter parameter = new Parameter(invoker.getExpr().getDesc());
                    parameter.insertParameter(wide ? Type.LONG_TYPE : Type.INT_TYPE, indexGroup);
                    System.out.println("-----[ " + boundFunc.getOwner() + "#" + boundFunc.getName() + " ]-----");
                    System.out.println("\n" + Arrays.stream(((DynamicInvocationExpr) invoker.getExpr()).getArgumentExprs()).map(Expr::getType).map(Object::toString).collect(Collectors.joining("\n")) + "\n");
                    System.out.println("\n" + Arrays.stream(((DynamicInvocationExpr) invoker.getExpr()).getBootstrapArgs()).map(Object::toString).collect(Collectors.joining("\n")) + "\n");
                    System.out.println(invoker.getExpr().getDesc()  + " new: " + parameter.getDesc());
                    System.out.println(boundFunc.getDesc() + " new " + newBoundFunc.getDesc());
                    invoker.getExpr().setDesc(parameter.getDesc());

                    ((DynamicInvocationExpr) invoker.getExpr()).getBootstrapArgs()[1] = newBoundFunc;
                } else {
                    final Parameter parameter = new Parameter(invoker.getExpr().getDesc());
                    parameter.insertParameter(wide ? Type.LONG_TYPE : Type.INT_TYPE, indexGroup);
                }
            }
        }

        final int finalStackHeight = stackHeight;
        skidGroup.setDesc(parameterGroup.getDesc());
        skidGroup.setStackHeight(finalStackHeight);
        skidGroup.setInjectedMethodPredicate(true);
    }

    private boolean hasFragileMethodOwner(final SkidGroup skidGroup) {
        return skidGroup.getMethodNodeList().stream()
                .filter(methodNode -> methodNode != null && methodNode.owner != null && methodNode.owner.node != null)
                .anyMatch(methodNode -> isFragileClass(methodNode.owner.node));
    }

    private boolean hasFragileInvokerOwner(final SkidGroup skidGroup) {
        return skidGroup.getInvokers().stream()
                .map(SkidInvocation::getOwner)
                .filter(methodNode -> methodNode != null && methodNode.owner != null && methodNode.owner.node != null)
                .anyMatch(methodNode -> isFragileClass(methodNode.owner.node));
    }

    private boolean isFragileClass(final org.objectweb.asm.tree.ClassNode classNode) {
        return classNode.outerClass != null
                || classNode.nestHostClass != null
                || ((classNode.access & Opcodes.ACC_SYNTHETIC) != 0)
                || (classNode.innerClasses != null
                && classNode.innerClasses.stream().anyMatch(innerClass -> classNode.name.equals(innerClass.name)));
    }

    private boolean threadStaticMethods() {
        return getConfig().getBoolean("threadStaticMethods", true);
    }

    /**
     * Method called when the class methods are iterated over and initialized.
     * In this we'll set the flow obfuscation opaque predicate getter and setter.
     *
     * @param event Method initializer event
     */
    @Listen
    void handle(final InitMethodTransformEvent event) {
        final SkidMethodNode methodNode = event.getMethodNode();
        final BlockOpaquePredicate flowPredicate = methodNode.getFlowPredicate();

        final MethodOpaquePredicate methodPredicate = methodNode.getPredicate();

        if (methodPredicate == null)
            return;

        methodPredicate.setGetter(new PredicateFlowGetter() {
            @Override
            public Expr get(final BasicBlock vertex) {
                if (skidfuscator.getConfig().isSeedWide()) {
                    // Under seed.wide the seed parameter is a long; project to int
                    // via L2I so we never ILOAD a long-occupied slot (verify error).
                    return new CastExpr(build(vertex, true), Type.INT_TYPE);
                }
                return build(vertex, false);
            }

            @Override
            public Expr getWide(final BasicBlock vertex) {
                return build(vertex, true);
            }

            private Expr build(final BasicBlock vertex, final boolean wide) {
                final SkidMethodNode skidMethodNode = (SkidMethodNode) vertex.cfg.getMethodNode();
                final SkidClassNode skidClassNode = (SkidClassNode) skidMethodNode.owner;

                final ClassOpaquePredicate classPredicate = skidMethodNode.isStatic()
                        ? skidMethodNode.getParent().getStaticPredicate()
                        : skidMethodNode.getParent().getClassPredicate();

                // Base class seed (int) and the getter that loads it at runtime.
                final int classSeed;
                final PredicateFlowGetter classGetter;
                if (skidMethodNode.isClinit() || skidMethodNode.isInit()) {
                    final int randomSeed = skidClassNode.getRandomInt();
                    classSeed = randomSeed;
                    classGetter = FlowFactoryMakerTransformer.materializeSeedGetter(
                            skidMethodNode.getSkidfuscator(),
                            skidClassNode,
                            randomSeed,
                            vertex1 -> new SkidIntegerParseStaticInvocationExpr(randomSeed)
                    );
                } else {
                    classSeed = classPredicate.get();
                    classGetter = classPredicate.getGetter();
                }

                final boolean injected = skidMethodNode.getGroup().isInjectedMethodPredicate();

                if (!wide) {
                    int seed = classSeed;
                    PredicateFlowGetter expr = classGetter;

                    if (injected) {
                        seed = seed ^ skidMethodNode.getGroup().getPredicate().getPublic();

                        final PredicateFlowGetter previousExprGetter = expr;
                        expr = vertex2 -> {
                            final ControlFlowGraph cfg = vertex2.getGraph();

                            return new ArithmeticExpr(
                                    /* Get the seed from the parameter */
                                    new VarExpr(
                                            cfg.getLocals().get(skidMethodNode.getGroup().getStackHeight()),
                                            Type.INT_TYPE
                                    ),
                                    /* Hash the previous instruction */
                                    previousExprGetter.get(vertex2),
                                    /* Obv xor operation */
                                    ArithmeticExpr.Operator.XOR
                            );
                        };
                    }

                    if (injected && skidfuscator.getConfig().getNativeConfig()
                            .getThreadedKeyConfig().isEnabled()) {
                        return skidfuscator.getNativeThreadedKeys().reconstruct(
                                skidMethodNode, false, methodPredicate.getPrivate(), seed, expr.get(vertex));
                    }
                    return NumberManager.encrypt(
                            methodPredicate.getPrivate(),
                            seed,
                            vertex,
                            expr
                    );
                }

                /*
                 * seed.wide: reconstruct the full 64-bit getPrivateLong(). The class
                 * seed is sign-extended (I2L) to a long; for injected methods the
                 * high entropy is carried by the 64-bit parameter (getPublicLong).
                 *
                 *   non-injected: (priv ^ (long)cs) ^ (long)cs                       == priv
                 *   injected:     (priv ^ (long)cs ^ pub) ^ (paramLong ^ (long)cs)   == priv
                 */
                long startingLong = (long) classSeed;
                PredicateFlowGetter exprWide =
                        vertex2 -> new CastExpr(classGetter.get(vertex2), Type.LONG_TYPE);

                if (injected) {
                    startingLong = ((long) classSeed)
                            ^ skidMethodNode.getGroup().getPredicate().getPublicLong();

                    final PredicateFlowGetter previousWideGetter = exprWide;
                    exprWide = vertex2 -> {
                        final ControlFlowGraph cfg = vertex2.getGraph();

                        return new ArithmeticExpr(
                                /* The 64-bit seed parameter */
                                new VarExpr(
                                        cfg.getLocals().get(skidMethodNode.getGroup().getStackHeight()),
                                        Type.LONG_TYPE
                                ),
                                /* (long) class seed, sign-extended */
                                previousWideGetter.get(vertex2),
                                ArithmeticExpr.Operator.XOR
                        );
                    };
                }

                if (injected && skidfuscator.getConfig().getNativeConfig()
                        .getThreadedKeyConfig().isEnabled()) {
                    return skidfuscator.getNativeThreadedKeys().reconstruct(
                            skidMethodNode, true, methodPredicate.getPrivateLong(), startingLong,
                            exprWide.getWide(vertex));
                }
                return NumberManager.encryptLong(
                        methodPredicate.getPrivateLong(),
                        startingLong,
                        vertex,
                        exprWide
                );
            }
        });
    }
}
