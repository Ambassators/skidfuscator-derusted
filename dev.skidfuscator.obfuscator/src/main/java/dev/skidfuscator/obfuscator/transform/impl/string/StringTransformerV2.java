package dev.skidfuscator.obfuscator.transform.impl.string;

import dev.skidfuscator.obfuscator.Skidfuscator;
import dev.skidfuscator.obfuscator.event.annotation.Listen;
import dev.skidfuscator.obfuscator.event.impl.transform.clazz.FinalClassTransformEvent;
import dev.skidfuscator.obfuscator.event.impl.transform.method.RunMethodTransformEvent;
import dev.skidfuscator.obfuscator.event.impl.transform.skid.PostSkidTransformEvent;
import dev.skidfuscator.obfuscator.skidasm.SkidClassNode;
import dev.skidfuscator.obfuscator.skidasm.SkidMethodNode;
import dev.skidfuscator.obfuscator.skidasm.cfg.SkidBlock;
import dev.skidfuscator.obfuscator.skidasm.expr.SkidConstantExpr;
import dev.skidfuscator.obfuscator.transform.AbstractTransformer;
import dev.skidfuscator.obfuscator.transform.Transformer;
import dev.skidfuscator.obfuscator.transform.impl.string.generator.EncryptionGeneratorV3;
import dev.skidfuscator.obfuscator.transform.impl.string.generator.v3.Base64PaddedV3EncryptionGenerator;
import dev.skidfuscator.obfuscator.util.RandomUtil;
import dev.skidfuscator.obfuscator.util.TypeUtil;
import org.mapleir.asm.ClassNode;
import org.mapleir.asm.FieldNode;
import org.mapleir.ir.cfg.ControlFlowGraph;
import org.mapleir.ir.code.CodeUnit;
import org.mapleir.ir.code.Expr;
import org.mapleir.ir.code.expr.ConstantExpr;
import org.mapleir.ir.code.expr.invoke.StaticInvocationExpr;

import java.util.*;
import java.util.stream.Collectors;
import java.util.concurrent.atomic.AtomicInteger;

public class StringTransformerV2 extends AbstractTransformer {
    private final List<String> noticeLiterals;
    private final AtomicInteger noticeSite = new AtomicInteger();
    private final Map<SkidClassNode, EncryptionGeneratorV3> keyMap = new HashMap<>();

    private final Set<String> INJECTED = new HashSet<>();

    public StringTransformerV2(Skidfuscator skidfuscator) {
        this(skidfuscator, Collections.emptyList());
    }

    public StringTransformerV2(Skidfuscator skidfuscator, List<Transformer> children) {
        super(skidfuscator, "String Encryption", children);
        if (skidfuscator.getConfig().getBoolean("stringEncryption.noticeXor.enabled", false)) {
            final String keyFile = skidfuscator.getConfig().getString("stringEncryption.noticeXor.keyFile", "");
            if (keyFile.trim().isEmpty()) {
                throw new IllegalArgumentException("stringEncryption.noticeXor.keyFile is required");
            }
            noticeLiterals = NoticeXorPad.read(java.nio.file.Paths.get(keyFile));
        } else {
            noticeLiterals = Collections.emptyList();
        }
    }

    @Listen
    void handle(final RunMethodTransformEvent event) {
        final SkidMethodNode methodNode = event.getMethodNode();

        if (shouldSkipMethod(methodNode)) {
            this.skip();
            return;
        }

        if (methodNode.node.instructions.size() > 10000) {
            this.fail();
            return;
        }

        final ControlFlowGraph cfg = methodNode.getCfg();

        if (cfg == null) {
            this.fail();
            return;
        }

        final SkidClassNode parentNode = methodNode.getParent();

        EncryptionGeneratorV3 generator = keyMap.get(parentNode);

        if (generator == null) {
            keyMap.put(parentNode, (generator = createGenerator(parentNode)));
        }

        if (!INJECTED.contains(parentNode.getName())) {
            generator.visitPre((SkidClassNode) methodNode.owner);
            INJECTED.add(parentNode.getName());
        }

        EncryptionGeneratorV3 finalGenerator = generator;
        cfg.allExprStream()
                /*
                 *
                 */
                .filter(SkidConstantExpr.class::isInstance)
                .map(SkidConstantExpr.class::cast)
                .filter(e -> !e.isExempt())
                .filter(e -> !methodNode.isInit() || !e.getBlock().isFlagSet(SkidBlock.FLAG_NO_OPAQUE))
                .filter(constantExpr -> constantExpr.getConstant() instanceof String)
                /*
                 * We collect since we're modifying the expression stream
                 * we kinda need to just not cause any concurrency issue.
                 * ¯\_(ツ)_/¯
                 */
                .collect(Collectors.toList())
                .forEach(unit -> {
                    final CodeUnit parent = unit.getParent();
                    final String constant = (String) unit.getConstant();
                    final SkidBlock block = (SkidBlock) unit.getBlock();

                    final Expr encrypted;
                    if (noticeLiterals.isEmpty()) {
                        encrypted = finalGenerator.encrypt(constant, methodNode, block);
                    } else {
                        final String notice = noticeLiterals.get(
                                Math.floorMod(noticeSite.getAndIncrement(), noticeLiterals.size()));
                        final Expr protectedValue = finalGenerator.encrypt(
                                NoticeXorPad.stage(constant, notice), methodNode, block);
                        encrypted = new StaticInvocationExpr(
                                new Expr[]{protectedValue, new ConstantExpr(notice, TypeUtil.STRING_TYPE)},
                                "sdk/NoticeStrings", "finish",
                                "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;");
                    }

                    try {
                        parent.overwrite(unit, encrypted);
                    } catch (IllegalStateException e) {
                        return;
                    }
                });
        this.success();
    }

    protected EncryptionGeneratorV3 createGenerator(final SkidClassNode parentNode) {
        return new Base64PaddedV3EncryptionGenerator(createRandomPad());
    }

    protected byte[] createRandomPad() {
        final int size = RandomUtil.nextInt(96) + 32;
        final byte[] pad = new byte[size];

        for (int i = 0; i < size; i++) {
            pad[i] = (byte) (RandomUtil.nextInt(255) + 1);
        }

        return pad;
    }

    @Listen
    void handle(final PostSkidTransformEvent event) {
        keyMap.forEach((clazz, generator) -> generator.visitPost(clazz));
    }

    /*
     * javac inlining is not proof that a field has no reflective, external or
     * bytecode getstatic consumers. Pinned ConstantValue fields retain their
     * values. Stripping other field attributes is an explicit closed-world
     * option; ordinary literal encryption remains active regardless.
     */
    @Listen
    void handle(final FinalClassTransformEvent event) {
        final SkidClassNode classNode = event.getClassNode();
        if (!skidfuscator.getConfig().getBoolean("stringEncryption.stripUnreferencedPrivateConstantFields", false)) return;

        for (FieldNode field : classNode.getFields()) {
            if (field.node.value instanceof String && field.isPrivate()
                    && !skidfuscator.isRuntimeFieldContract(field.node)) {
                field.node.value = null;
                this.success();
            }
        }
    }
}
