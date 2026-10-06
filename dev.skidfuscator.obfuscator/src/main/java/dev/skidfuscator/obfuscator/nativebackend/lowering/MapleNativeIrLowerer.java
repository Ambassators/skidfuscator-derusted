package dev.skidfuscator.obfuscator.nativebackend.lowering;

import dev.skidfuscator.nativeir.JavaDescriptor;
import dev.skidfuscator.nativeir.NativeBackend;
import dev.skidfuscator.nativeir.NativeBlock;
import dev.skidfuscator.nativeir.NativeExceptionEdge;
import dev.skidfuscator.nativeir.NativeFunction;
import dev.skidfuscator.nativeir.NativeInstruction;
import dev.skidfuscator.nativeir.NativeIrVerificationException;
import dev.skidfuscator.nativeir.NativeIrVerifier;
import dev.skidfuscator.nativeir.NativeIrVersions;
import dev.skidfuscator.nativeir.NativeModule;
import dev.skidfuscator.nativeir.NativeOpcode;
import dev.skidfuscator.nativeir.NativeOperand;
import dev.skidfuscator.nativeir.NativeParameter;
import dev.skidfuscator.nativeir.NativeTerminator;
import dev.skidfuscator.nativeir.NativeType;
import dev.skidfuscator.nativeir.SourceLocation;
import dev.skidfuscator.obfuscator.skidasm.SkidMethodNode;
import dev.skidfuscator.obfuscator.skidasm.stmt.SkidBogusStmt;
import org.mapleir.asm.MethodNode;
import org.mapleir.flowgraph.ExceptionRange;
import org.mapleir.flowgraph.edges.FlowEdge;
import org.mapleir.flowgraph.edges.TryCatchEdge;
import org.mapleir.ir.TypeUtils;
import org.mapleir.ir.cfg.BasicBlock;
import org.mapleir.ir.cfg.ControlFlowGraph;
import org.mapleir.ir.code.Expr;
import org.mapleir.ir.code.Stmt;
import org.mapleir.ir.code.expr.AllocObjectExpr;
import org.mapleir.ir.code.expr.ArithmeticExpr;
import org.mapleir.ir.code.expr.ArrayLengthExpr;
import org.mapleir.ir.code.expr.ArrayLoadExpr;
import org.mapleir.ir.code.expr.CastExpr;
import org.mapleir.ir.code.expr.CaughtExceptionExpr;
import org.mapleir.ir.code.expr.ComparisonExpr;
import org.mapleir.ir.code.expr.ConstantExpr;
import org.mapleir.ir.code.expr.FieldLoadExpr;
import org.mapleir.ir.code.expr.InstanceofExpr;
import org.mapleir.ir.code.expr.NegationExpr;
import org.mapleir.ir.code.expr.NewArrayExpr;
import org.mapleir.ir.code.expr.PhiExpr;
import org.mapleir.ir.code.expr.VarExpr;
import org.mapleir.ir.code.expr.invoke.DynamicInvocationExpr;
import org.mapleir.ir.code.expr.invoke.InitialisedObjectExpr;
import org.mapleir.ir.code.expr.invoke.InvocationExpr;
import org.mapleir.ir.code.stmt.ArrayStoreStmt;
import org.mapleir.ir.code.stmt.ConditionalJumpStmt;
import org.mapleir.ir.code.stmt.FieldStoreStmt;
import org.mapleir.ir.code.stmt.FrameStmt;
import org.mapleir.ir.code.stmt.LineNumberStmt;
import org.mapleir.ir.code.stmt.MonitorStmt;
import org.mapleir.ir.code.stmt.NopStmt;
import org.mapleir.ir.code.stmt.PopStmt;
import org.mapleir.ir.code.stmt.ReturnStmt;
import org.mapleir.ir.code.stmt.SwitchStmt;
import org.mapleir.ir.code.stmt.ThrowStmt;
import org.mapleir.ir.code.stmt.UnconditionalJumpStmt;
import org.mapleir.ir.code.stmt.copy.AbstractCopyStmt;
import org.mapleir.ir.code.stmt.copy.CopyPhiStmt;
import org.mapleir.ir.locals.Local;
import org.mapleir.ir.locals.impl.VersionedLocal;
import org.objectweb.asm.ConstantDynamic;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.LineNumberNode;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Lowers a finalized MapleIR SSA graph into the target-neutral native IR.
 *
 * <p>The lowerer is read-only with respect to both MapleIR and ASM. It either returns a module
 * accepted by {@link NativeIrVerifier}, or raises a typed {@link NativeLoweringException}. Java
 * operations whose exact behavior belongs in the JNI semantic runtime are represented explicitly;
 * the LLVM emitter remains responsible for rejecting them until that runtime is linked.</p>
 */
public final class MapleNativeIrLowerer {
    private static final Pattern LINKABLE_SYMBOL = Pattern.compile("[A-Za-z_][A-Za-z0-9_]*");
    private static final NativeType.Reference STRING_TYPE =
            new NativeType.Reference("java/lang/String", false);
    private static final NativeType.Reference OBJECT_TYPE =
            new NativeType.Reference("java/lang/Object", true);

    private final NativeIrVerifier verifier;
    private final JavaLinkageBridgeRegistry linkageBridges;

    public MapleNativeIrLowerer() {
        this(new NativeIrVerifier(), null);
    }

    MapleNativeIrLowerer(final NativeIrVerifier verifier) {
        this(verifier, null);
    }

    public MapleNativeIrLowerer(final JavaLinkageBridgeRegistry linkageBridges) {
        this(new NativeIrVerifier(), Objects.requireNonNull(linkageBridges, "linkageBridges"));
    }

    MapleNativeIrLowerer(
            final NativeIrVerifier verifier,
            final JavaLinkageBridgeRegistry linkageBridges
    ) {
        this.verifier = Objects.requireNonNull(verifier, "verifier");
        this.linkageBridges = linkageBridges;
    }

    /** Lowers the finalized graph owned by a Skid method. */
    public NativeModule lower(
            final String moduleName,
            final String emittedSymbol,
            final MethodNode method,
            final NativeBackend backend
    ) {
        validateBoundary(moduleName, emittedSymbol, method, backend);
        if (method instanceof SkidMethodNode skidMethod) {
            return lower(moduleName, emittedSymbol, method, skidMethod.getCfg(), backend);
        }

        // A small ASM-only compatibility path is retained for callers which do not own a Maple CFG.
        return lowerAsmStringLiteral(moduleName, emittedSymbol, method, backend);
    }

    /**
     * Lowers an explicitly supplied finalized Maple graph. This overload is useful to pipeline
     * stages which have a graph snapshot and to focused tests which construct MapleIR directly.
     */
    public NativeModule lower(
            final String moduleName,
            final String emittedSymbol,
            final MethodNode method,
            final ControlFlowGraph cfg,
            final NativeBackend backend
    ) {
        validateBoundary(moduleName, emittedSymbol, method, backend);
        Objects.requireNonNull(cfg, "cfg");
        if (cfg.getMethodNode() != method) {
            throw failure(method, NativeLoweringException.Reason.INVALID_METHOD, cfg,
                    "the supplied Maple graph belongs to a different method");
        }
        try {
            final LoweringSession session = new LoweringSession(
                    method, cfg, backend, emittedSymbol, linkageBridges);
            final NativeFunction function = session.lower();
            final NativeModule module = new NativeModule(
                    moduleName,
                    NativeIrVersions.CURRENT_ABI,
                    Map.of("lowerer", "maple-ssa-v2")
            ).addFunction(function);
            verifier.verifyOrThrow(module);
            return module;
        } catch (final NativeIrVerificationException exception) {
            throw new NativeLoweringException(
                    NativeLoweringException.Reason.VERIFICATION_FAILED,
                    methodName(method),
                    NativeIrVerifier.class.getSimpleName(),
                    "Cannot lower " + methodName(method) + ": " + exception.getMessage(),
                    exception
            );
        } catch (final NativeLoweringException exception) {
            throw exception;
        } catch (final RuntimeException exception) {
            throw new NativeLoweringException(
                    NativeLoweringException.Reason.INVALID_CONTROL_FLOW,
                    methodName(method),
                    cfg.getClass().getSimpleName(),
                    "Cannot lower " + methodName(method) + ": malformed finalized MapleIR: "
                            + exception.getMessage(),
                    exception
            );
        }
    }

    public Support check(final MethodNode method) {
        Objects.requireNonNull(method, "method");
        try {
            lower("skid-native-probe", "skid_probe", method, NativeBackend.AOT);
            return new Support(true, "", null);
        } catch (final NativeLoweringException exception) {
            return new Support(false, exception.getMessage(), exception.reason());
        }
    }

    public Support check(final MethodNode method, final ControlFlowGraph cfg) {
        Objects.requireNonNull(method, "method");
        Objects.requireNonNull(cfg, "cfg");
        try {
            lower("skid-native-probe", "skid_probe", method, cfg, NativeBackend.AOT);
            return new Support(true, "", null);
        } catch (final NativeLoweringException exception) {
            return new Support(false, exception.getMessage(), exception.reason());
        }
    }

    /**
     * Lowers only the proven post-initialization tail of a constructor. The resulting function is
     * registered as the supplied synthetic static helper and therefore receives initialized
     * {@code this} followed by the constructor's original arguments.
     */
    public NativeModule lowerConstructorTail(
            final String moduleName,
            final String emittedSymbol,
            final String helperJavaName,
            final MethodNode constructor,
            final ControlFlowGraph cfg,
            final ConstructorTailAnalyzer.Result plan,
            final NativeBackend backend
    ) {
        validateBoundary(moduleName, emittedSymbol, constructor, backend);
        Objects.requireNonNull(helperJavaName, "helperJavaName");
        Objects.requireNonNull(cfg, "cfg");
        Objects.requireNonNull(plan, "plan");
        if (!"<init>".equals(constructor.getName())) {
            throw failure(constructor, NativeLoweringException.Reason.INVALID_METHOD, constructor,
                    "constructor-tail lowering requires <init>");
        }
        if (!plan.supported()) {
            throw failure(constructor, NativeLoweringException.Reason.UNSUPPORTED_METHOD, constructor,
                    "constructor tail is not proven safe: " + plan.reason());
        }
        if (helperJavaName.isBlank() || helperJavaName.startsWith("<")) {
            throw failure(constructor, NativeLoweringException.Reason.INVALID_METHOD, constructor,
                    "synthetic native helper name is invalid: " + helperJavaName);
        }
        final ConstructorTailAnalyzer.Result current = new ConstructorTailAnalyzer().analyze(constructor, cfg);
        if (!current.equals(plan)) {
            throw failure(constructor, NativeLoweringException.Reason.INVALID_CONTROL_FLOW, cfg,
                    "constructor graph changed after its tail safety proof");
        }
        try {
            final LoweringSession session = new LoweringSession(
                    constructor, cfg, backend, emittedSymbol, plan, helperJavaName, linkageBridges);
            final NativeFunction function = session.lower();
            final NativeModule module = new NativeModule(
                    moduleName, NativeIrVersions.CURRENT_ABI,
                    Map.of("lowerer", "maple-constructor-tail-v1"))
                    .addFunction(function);
            verifier.verifyOrThrow(module);
            return module;
        } catch (final NativeIrVerificationException exception) {
            throw new NativeLoweringException(
                    NativeLoweringException.Reason.VERIFICATION_FAILED,
                    methodName(constructor), NativeIrVerifier.class.getSimpleName(),
                    "Cannot lower constructor tail " + methodName(constructor) + ": "
                            + exception.getMessage(), exception);
        }
    }

    private static void validateBoundary(
            final String moduleName,
            final String emittedSymbol,
            final MethodNode method,
            final NativeBackend backend
    ) {
        Objects.requireNonNull(moduleName, "moduleName");
        Objects.requireNonNull(emittedSymbol, "emittedSymbol");
        Objects.requireNonNull(method, "method");
        Objects.requireNonNull(backend, "backend");
        if (moduleName.isBlank()) {
            throw new IllegalArgumentException("moduleName cannot be blank");
        }
        if (!LINKABLE_SYMBOL.matcher(emittedSymbol).matches()) {
            throw new NativeLoweringException(
                    NativeLoweringException.Reason.INVALID_METHOD,
                    methodName(method),
                    "symbol",
                    "Emitted symbol must be directly linkable from a native trampoline: " + emittedSymbol
            );
        }
        final int forbidden = Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE;
        if ((method.node.access & forbidden) != 0) {
            throw failure(method, NativeLoweringException.Reason.UNSUPPORTED_METHOD, method,
                    "abstract and already-native methods cannot be lowered");
        }
        try {
            JavaDescriptor.method(method.getDesc());
        } catch (final IllegalArgumentException exception) {
            throw failure(method, NativeLoweringException.Reason.INVALID_METHOD, method,
                    "invalid method descriptor " + method.getDesc());
        }
    }

    private NativeModule lowerAsmStringLiteral(
            final String moduleName,
            final String emittedSymbol,
            final MethodNode method,
            final NativeBackend backend
    ) {
        if (!"()Ljava/lang/String;".equals(method.getDesc()) || !method.isStatic()) {
            throw failure(method, NativeLoweringException.Reason.UNSUPPORTED_METHOD, method,
                    "a finalized MapleIR graph is required for this method");
        }
        final List<AbstractInsnNode> executable = new ArrayList<>();
        int firstLine = -1;
        int offset = 0;
        int literalOffset = -1;
        for (AbstractInsnNode instruction = method.node.instructions.getFirst();
             instruction != null;
             instruction = instruction.getNext()) {
            if (instruction instanceof LineNumberNode line && firstLine < 0) {
                firstLine = line.line;
            }
            if (instruction.getOpcode() >= 0) {
                if (executable.isEmpty()) literalOffset = offset;
                executable.add(instruction);
                offset++;
            }
        }
        if (executable.size() != 2
                || !(executable.get(0) instanceof LdcInsnNode load)
                || !(load.cst instanceof String value)
                || executable.get(1).getOpcode() != Opcodes.ARETURN) {
            throw failure(method, NativeLoweringException.Reason.UNSUPPORTED_METHOD, method,
                    "a finalized MapleIR graph is required; the ASM fallback accepts exactly LDC <String>; ARETURN");
        }
        final SourceLocation location = new SourceLocation(sourceFile(method), firstLine, literalOffset);
        final NativeInstruction.Operation literal = new NativeInstruction.Operation(
                "string.constant", STRING_TYPE, NativeOpcode.STRING_CONSTANT, List.of(),
                Map.of("value", value), location
        );
        final NativeBlock entry = new NativeBlock("entry")
                .addInstruction(literal)
                .terminate(new NativeTerminator.Return(
                        Optional.of(new NativeOperand.Value(literal.id(), literal.type())), location));
        final NativeFunction function = new NativeFunction(
                emittedSymbol, method.owner.getName(), method.getName(), method.getDesc(), STRING_TYPE,
                List.of(), entry.id(), backend, false, true,
                Map.of("lowering", "asm-static-string-compat-v1", "semanticContext", "jni",
                        "java.static", "true")
        ).addBlock(entry);
        final NativeModule module = new NativeModule(moduleName, NativeIrVersions.CURRENT_ABI,
                Map.of("lowerer", "asm-static-string-compat-v1")).addFunction(function);
        verifier.verifyOrThrow(module);
        return module;
    }

    public record Support(
            boolean supported,
            String reason,
            NativeLoweringException.Reason reasonCode
    ) {
        public Support {
            Objects.requireNonNull(reason, "reason");
            if (supported && (!reason.isEmpty() || reasonCode != null)) {
                throw new IllegalArgumentException("A supported result cannot contain a rejection reason");
            }
            if (!supported && (reason.isBlank() || reasonCode == null)) {
                throw new IllegalArgumentException("An unsupported result requires a typed reason");
            }
        }
    }

    private static final class LoweringSession {
        private final MethodNode method;
        private final ControlFlowGraph cfg;
        private final NativeBackend backend;
        private final String emittedSymbol;
        private final JavaLinkageBridgeRegistry linkageBridges;
        private final List<BasicBlock> blocks;
        private final BasicBlock entryBlock;
        private final Map<BasicBlock, Integer> firstStatements;
        private final String javaName;
        private final String javaDescriptor;
        private final boolean constructorTail;
        private final Map<BasicBlock, NativeBlock> nativeBlocks = new LinkedHashMap<>();
        private final Map<Local, Definition> definitions = new HashMap<>();
        private final Map<Integer, ParameterBinding> parametersBySlot = new HashMap<>();
        private final List<NativeParameter> parameters = new ArrayList<>();
        private int temporary;
        private boolean requiresSemanticContext;

        private LoweringSession(
                final MethodNode method,
                final ControlFlowGraph cfg,
                final NativeBackend backend,
                final String emittedSymbol,
                final JavaLinkageBridgeRegistry linkageBridges
        ) {
            this.method = method;
            this.cfg = cfg;
            this.backend = backend;
            this.emittedSymbol = emittedSymbol;
            this.linkageBridges = linkageBridges;
            this.blocks = cfg.vertices().stream()
                    .sorted(Comparator.comparingInt(BasicBlock::getNumericId))
                    .toList();
            this.entryBlock = cfg.getEntries().iterator().next();
            this.firstStatements = Map.of();
            this.javaName = method.getName();
            this.javaDescriptor = method.getDesc();
            this.constructorTail = false;
        }

        private LoweringSession(
                final MethodNode method,
                final ControlFlowGraph cfg,
                final NativeBackend backend,
                final String emittedSymbol,
                final ConstructorTailAnalyzer.Result plan,
                final String helperJavaName,
                final JavaLinkageBridgeRegistry linkageBridges
        ) {
            this.method = method;
            this.cfg = cfg;
            this.backend = backend;
            this.emittedSymbol = emittedSymbol;
            this.linkageBridges = linkageBridges;
            final Map<String, BasicBlock> byId = cfg.vertices().stream().collect(Collectors.toMap(
                    MapleNativeIrLowerer::blockId, block -> block));
            this.blocks = plan.tailBlocks().stream().map(byId::get)
                    .filter(Objects::nonNull)
                    .sorted(Comparator.comparingInt(BasicBlock::getNumericId))
                    .toList();
            this.entryBlock = byId.get(plan.boundaryBlock());
            if (entryBlock == null || blocks.size() != plan.tailBlocks().size()) {
                throw failure(method, NativeLoweringException.Reason.INVALID_CONTROL_FLOW, cfg,
                        "constructor tail proof names blocks outside the finalized graph");
            }
            this.firstStatements = Map.of(entryBlock, plan.firstTailStatement());
            this.javaName = helperJavaName;
            this.javaDescriptor = plan.helperDescriptor();
            this.constructorTail = true;
        }

        private NativeFunction lower() {
            if (cfg.getEntries().size() != 1) {
                throw failure(method, NativeLoweringException.Reason.INVALID_CONTROL_FLOW, cfg,
                        "expected exactly one entry block, found " + cfg.getEntries().size());
            }
            if (blocks.isEmpty()) {
                throw failure(method, NativeLoweringException.Reason.INVALID_CONTROL_FLOW, cfg,
                        "the finalized graph has no blocks");
            }
            createParameters();
            predeclareBlocksAndDefinitions();
            promoteBoundaryParameters();
            lowerBlocks();
            addExceptionEdges();

            final NativeType returnType = nativeType(Type.getReturnType(method.getDesc()), true);
            final String entry = blockId(entryBlock);
            final boolean synchronizedMethod = (method.node.access & Opcodes.ACC_SYNCHRONIZED) != 0;
            if (synchronizedMethod) requiresSemanticContext = true;
            final NativeFunction function = new NativeFunction(
                    emittedSymbol, method.owner.getName(), javaName, javaDescriptor, returnType,
                    parameters, entry, backend, synchronizedMethod, requiresSemanticContext,
                    Map.of(
                            "lowering", "maple-ssa-v2",
                            "semanticContext", requiresSemanticContext ? "jni" : "none",
                            "java.static", Boolean.toString(method.isStatic() || constructorTail),
                            "java.final", Boolean.toString((method.node.access & Opcodes.ACC_FINAL) != 0),
                            "java.private", Boolean.toString((method.node.access & Opcodes.ACC_PRIVATE) != 0),
                            "java.classFinal", Boolean.toString((method.owner.node.access & Opcodes.ACC_FINAL) != 0),
                            "java.synchronized", Boolean.toString(synchronizedMethod),
                            "constructor.tail", Boolean.toString(constructorTail),
                            "constructor.originalDescriptor", constructorTail ? method.getDesc() : ""
                    )
            );
            blocks.forEach(block -> function.addBlock(nativeBlocks.get(block)));
            return function;
        }

        private void createParameters() {
            int parameterIndex = 0;
            int slot = 0;
            if (!method.isStatic()) {
                final NativeType type = new NativeType.Reference(method.owner.getName(), true);
                final NativeParameter parameter = new NativeParameter("arg" + parameterIndex, type, parameterIndex);
                parameters.add(parameter);
                parametersBySlot.put(slot, new ParameterBinding(parameter, Type.getObjectType(method.owner.getName())));
                parameterIndex++;
                slot++;
            }
            for (final Type argument : Type.getArgumentTypes(method.getDesc())) {
                final NativeType type = nativeType(argument, true);
                final NativeParameter parameter = new NativeParameter("arg" + parameterIndex, type, parameterIndex);
                parameters.add(parameter);
                parametersBySlot.put(slot, new ParameterBinding(parameter, argument));
                parameterIndex++;
                slot += argument.getSize();
            }
        }

        private final Map<Integer, NativeOperand> promotedParameters = new HashMap<>();

        private void promoteBoundaryParameters() {
            // JVM local slots use int computational values for boolean/byte/short/char.
            // Keep JNI parameter widths at the boundary and widen once in the entry.
            final NativeBlock entry = nativeBlocks.get(entryBlock);
            for (var binding : parametersBySlot.entrySet()) {
                final NativeParameter parameter = binding.getValue().parameter();
                final NativeType widened = localValueType(binding.getValue().asmType());
                if (widened.equals(parameter.type())) continue;
                final int sort = binding.getValue().asmType().getSort();
                final String id = "parameter.promoted." + parameter.index();
                entry.addInstruction(new NativeInstruction.Operation(id, widened, NativeOpcode.CONVERT,
                        List.of(new NativeOperand.Value(parameter.id(), parameter.type())),
                        Map.of("signed", Boolean.toString(sort != Type.CHAR && sort != Type.BOOLEAN)),
                        SourceLocation.UNKNOWN));
                promotedParameters.put(binding.getKey(), new NativeOperand.Value(id, widened));
            }
        }

        private void predeclareBlocksAndDefinitions() {
            for (final BasicBlock block : blocks) {
                nativeBlocks.put(block, new NativeBlock(blockId(block)));
                for (int statementIndex = firstStatements.getOrDefault(block, 0);
                     statementIndex < block.size(); statementIndex++) {
                    final Stmt stmt = block.get(statementIndex);
                    if (!(stmt instanceof AbstractCopyStmt copy) || copy.isSynthetic()) continue;
                    final Local local = copy.getVariable().getLocal();
                    final NativeType type = localValueType(copy.getVariable().getType());
                    final Definition definition = new Definition(
                            new NativeOperand.Value(localId(local), type), copy, block
                    );
                    final Definition previous = definitions.putIfAbsent(local, definition);
                    if (previous != null) {
                        throw failure(method, NativeLoweringException.Reason.NON_SSA_LOCAL, stmt,
                                "local " + local + " has multiple definitions; finalized MapleIR must be SSA");
                    }
                    if (!(local instanceof VersionedLocal)) {
                        final long count = blocks.stream().flatMap(value -> value.stream())
                                .filter(AbstractCopyStmt.class::isInstance)
                                .map(AbstractCopyStmt.class::cast)
                                .filter(value -> !value.isSynthetic() && value.getVariable().getLocal().equals(local))
                                .count();
                        if (count > 1) {
                            throw failure(method, NativeLoweringException.Reason.NON_SSA_LOCAL, stmt,
                                    "unversioned local " + local + " is assigned more than once");
                        }
                    }
                }
            }
        }

        private void lowerBlocks() {
            for (final BasicBlock block : blocks) {
                final NativeBlock output = nativeBlocks.get(block);
                boolean terminated = false;
                boolean sawNonPhi = false;
                int statementIndex = firstStatements.getOrDefault(block, 0);
                int sourceLine = -1;
                for (int cursor = statementIndex; cursor < block.size(); cursor++) {
                    final Stmt stmt = block.get(cursor);
                    if (stmt instanceof LineNumberStmt lineNumber) {
                        sourceLine = lineNumber.getLine();
                        statementIndex++;
                        continue;
                    }
                    final SourceLocation location = location(sourceLine, statementIndex++);
                    if (isMetadata(stmt)) continue;
                    if (terminated) {
                        throw failure(method, NativeLoweringException.Reason.INVALID_CONTROL_FLOW, stmt,
                                "executable statement appears after a control-flow terminator in " + blockId(block));
                    }
                    if (stmt instanceof CopyPhiStmt phiStore) {
                        if (sawNonPhi) {
                            throw failure(method, NativeLoweringException.Reason.INVALID_CONTROL_FLOW, stmt,
                                    "phi definition appears after an executable instruction");
                        }
                        lowerPhi(phiStore, output, location);
                    } else if (stmt instanceof AbstractCopyStmt copy) {
                        sawNonPhi = true;
                        if (!copy.isSynthetic()) {
                            final Definition definition = definition(copy.getVariable().getLocal(), stmt);
                            final NativeOperand value = lowerExpression(copy.getExpression(), output, location,
                                    definition.value().id(), definition.value().type());
                            requireValue(copy.getExpression(), value);
                        }
                    } else if (stmt instanceof ArrayStoreStmt store) {
                        sawNonPhi = true;
                        lowerArrayStore(store, output, location);
                    } else if (stmt instanceof FieldStoreStmt store) {
                        sawNonPhi = true;
                        lowerFieldStore(store, output, location);
                    } else if (stmt instanceof MonitorStmt monitor) {
                        sawNonPhi = true;
                        lowerMonitor(monitor, output, location);
                    } else if (stmt instanceof PopStmt pop) {
                        sawNonPhi = true;
                        lowerExpression(pop.getExpression(), output, location, null,
                                nativeType(pop.getExpression().getType(), false));
                    } else if (stmt instanceof ReturnStmt returning) {
                        sawNonPhi = true;
                        lowerReturn(returning, output, location);
                        terminated = true;
                    } else if (stmt instanceof ConditionalJumpStmt branch) {
                        sawNonPhi = true;
                        lowerConditional(block, branch, output, location);
                        terminated = true;
                    } else if (stmt instanceof UnconditionalJumpStmt branch) {
                        sawNonPhi = true;
                        output.terminate(new NativeTerminator.Branch(blockId(branch.getTarget()), location));
                        terminated = true;
                    } else if (stmt instanceof SwitchStmt switching) {
                        sawNonPhi = true;
                        lowerSwitch(switching, output, location);
                        terminated = true;
                    } else if (stmt instanceof ThrowStmt throwing) {
                        sawNonPhi = true;
                        requiresSemanticContext = true;
                        final NativeOperand throwable = requireValue(throwing.getExpression(),
                                lowerExpression(throwing.getExpression(), output, location, null,
                                        nativeType(throwing.getExpression().getType(), false)));
                        output.terminate(new NativeTerminator.Throw(throwable, location));
                        terminated = true;
                    } else {
                        throw failure(method, NativeLoweringException.Reason.UNSUPPORTED_STATEMENT, stmt,
                                "unsupported MapleIR statement " + stmt.getClass().getName());
                    }
                }
                if (!terminated) {
                    final List<BasicBlock> successors = normalSuccessors(block);
                    if (successors.size() != 1) {
                        throw failure(method, NativeLoweringException.Reason.INVALID_CONTROL_FLOW, block,
                                "unterminated block has " + successors.size() + " normal successors");
                    }
                    output.terminate(new NativeTerminator.Branch(
                            blockId(successors.get(0)), location(sourceLine, statementIndex)));
                }
            }
        }

        private void lowerPhi(
                final CopyPhiStmt store,
                final NativeBlock output,
                final SourceLocation location
        ) {
            final Definition definition = definition(store.getVariable().getLocal(), store);
            final PhiExpr phi = store.getExpression();
            final List<NativeInstruction.Phi.Incoming> incoming = phi.getArguments().entrySet().stream()
                    .sorted(Map.Entry.comparingByKey(Comparator.comparingInt(BasicBlock::getNumericId)))
                    .map(entry -> new NativeInstruction.Phi.Incoming(
                            blockId(entry.getKey()),
                            purePhiOperand(entry.getValue(), definition.value().type())
                    ))
                    .toList();
            output.addInstruction(new NativeInstruction.Phi(
                    definition.value().id(), definition.value().type(), incoming, location));
        }

        private NativeOperand purePhiOperand(final Expr expression, final NativeType expected) {
            final NativeOperand operand;
            if (expression instanceof VarExpr variable) {
                operand = resolveVariable(variable);
            } else if (expression instanceof ConstantExpr constant
                    && !(constant.getConstant() instanceof String)
                    && !(constant.getConstant() instanceof Type)
                    && !(constant.getConstant() instanceof Handle)
                    && !(constant.getConstant() instanceof ConstantDynamic)) {
                operand = constantOperand(constant);
            } else {
                throw failure(method, NativeLoweringException.Reason.UNSUPPORTED_EXPRESSION, expression,
                        "phi input must be a local or inline primitive/null constant");
            }
            if (!operand.type().equals(expected)
                    && !(operand.type().isReferenceLike() && expected.isReferenceLike())) {
                throw failure(method, NativeLoweringException.Reason.TYPE_MISMATCH, expression,
                        "phi input type " + operand.type().displayName() + " does not match "
                                + expected.displayName());
            }
            return operand;
        }

        private void lowerReturn(
                final ReturnStmt returning,
                final NativeBlock output,
                final SourceLocation location
        ) {
            final NativeType expected = nativeType(Type.getReturnType(method.getDesc()), true);
            if (returning.getExpression() == null) {
                if (!expected.isVoid()) {
                    throw failure(method, NativeLoweringException.Reason.TYPE_MISMATCH, returning,
                            "non-void method contains a void return");
                }
                output.terminate(new NativeTerminator.Return(Optional.empty(), location));
                return;
            }
            if (expected.isVoid()) {
                throw failure(method, NativeLoweringException.Reason.TYPE_MISMATCH, returning,
                        "void method contains a value return");
            }
            final NativeOperand value = requireValue(returning.getExpression(), lowerExpression(
                    returning.getExpression(), output, location, null, expected));
            output.terminate(new NativeTerminator.Return(Optional.of(value), location));
        }

        private void lowerConditional(
                final BasicBlock block,
                final ConditionalJumpStmt branch,
                final NativeBlock output,
                final SourceLocation location
        ) {
            final NativeOperand left;
            final NativeOperand right;
            final Type commonAsm;
            try {
                commonAsm = TypeUtils.resolveBinOpType(branch.getLeft().getType(), branch.getRight().getType());
            } catch (final RuntimeException exception) {
                throw failure(method, NativeLoweringException.Reason.TYPE_MISMATCH, branch,
                        "cannot determine comparison operand type");
            }
            final NativeType common = TypeUtils.isObjectRef(commonAsm) ? OBJECT_TYPE : localValueType(commonAsm);
            if (common.isReferenceLike()) requiresSemanticContext = true;
            left = requireValue(branch.getLeft(), lowerExpression(branch.getLeft(), output, location, null, common));
            right = requireValue(branch.getRight(), lowerExpression(branch.getRight(), output, location, null, common));
            final NativeOpcode opcode = comparisonOpcode(branch.getComparisonType(), common);
            final String conditionId = temporary("condition");
            output.addInstruction(new NativeInstruction.Operation(
                    conditionId, NativeType.Primitive.I1, opcode, List.of(left, right), Map.of(), location));
            final BasicBlock falseTarget = falseTarget(block, branch.getTrueSuccessor());
            output.terminate(new NativeTerminator.ConditionalBranch(
                    new NativeOperand.Value(conditionId, NativeType.Primitive.I1),
                    blockId(branch.getTrueSuccessor()), blockId(falseTarget), location));
        }

        private void lowerSwitch(
                final SwitchStmt switching,
                final NativeBlock output,
                final SourceLocation location
        ) {
            final NativeOperand selector = requireValue(switching.getExpression(), lowerExpression(
                    switching.getExpression(), output, location, null, NativeType.Primitive.I32));
            final Map<Long, String> cases = switching.getTargets().entrySet().stream()
                    .sorted(Map.Entry.comparingByKey())
                    .collect(Collectors.toMap(
                            entry -> entry.getKey().longValue(),
                            entry -> blockId(entry.getValue()),
                            (left, right) -> left,
                            LinkedHashMap::new
                    ));
            output.terminate(new NativeTerminator.Switch(
                    selector, cases, blockId(switching.getDefaultTarget()), location));
        }

        private void lowerArrayStore(
                final ArrayStoreStmt store,
                final NativeBlock output,
                final SourceLocation location
        ) {
            final NativeOperand array = requireValue(store.getArrayExpression(), lowerExpression(
                    store.getArrayExpression(), output, location, null,
                    nativeType(store.getArrayExpression().getType(), false)));
            if (!(array.type() instanceof NativeType.Array arrayType)) {
                throw failure(method, NativeLoweringException.Reason.TYPE_MISMATCH, store,
                        "ARRAY_STORE receiver is not an array");
            }
            final NativeOperand index = requireValue(store.getIndexExpression(), lowerExpression(
                    store.getIndexExpression(), output, location, null, NativeType.Primitive.I32));
            final NativeOperand value = requireValue(store.getValueExpression(), lowerExpression(
                    store.getValueExpression(), output, location, null, arrayType.componentType()));
            semantic(output, new NativeInstruction.Operation(
                    temporary("array.store"), NativeType.Primitive.VOID, NativeOpcode.ARRAY_STORE,
                    List.of(array, index, value),
                    Map.of("descriptor", store.getArrayExpression().getType().getDescriptor()), location));
        }

        private void lowerFieldStore(
                final FieldStoreStmt store,
                final NativeBlock output,
                final SourceLocation location
        ) {
            final List<NativeOperand> operands = new ArrayList<>();
            if (!store.isStatic()) {
                operands.add(requireValue(store.getInstanceExpression(), lowerExpression(
                        store.getInstanceExpression(), output, location, null,
                        new NativeType.Reference(store.getOwner(), true))));
            }
            final NativeType fieldType = nativeType(Type.getType(store.getDesc()), true);
            operands.add(requireValue(store.getValueExpression(), lowerExpression(
                    store.getValueExpression(), output, location, null, fieldType)));
            semantic(output, new NativeInstruction.Operation(
                    temporary("field.set"), NativeType.Primitive.VOID, NativeOpcode.FIELD_SET, operands,
                    memberAttributes(store.getOwner(), store.getName(), store.getDesc(), store.isStatic()), location));
        }

        private void lowerMonitor(
                final MonitorStmt monitor,
                final NativeBlock output,
                final SourceLocation location
        ) {
            final NativeOperand value = requireValue(monitor.getExpression(), lowerExpression(
                    monitor.getExpression(), output, location, null,
                    nativeType(monitor.getExpression().getType(), false)));
            final NativeOpcode opcode = monitor.getMode() == MonitorStmt.MonitorMode.ENTER
                    ? NativeOpcode.MONITOR_ENTER : NativeOpcode.MONITOR_EXIT;
            semantic(output, new NativeInstruction.Operation(
                    temporary("monitor"), NativeType.Primitive.VOID, opcode, List.of(value), Map.of(), location));
        }

        private NativeOperand lowerExpression(
                final Expr expression,
                final NativeBlock output,
                final SourceLocation location,
                final String requestedId,
                final NativeType requestedType
        ) {
            Objects.requireNonNull(expression, "expression");
            final NativeOperand raw;
            if (expression instanceof ConstantExpr constant) {
                raw = lowerConstant(constant, output, location,
                        directId(requestedId, requestedType, constant.getConstant() instanceof String
                                ? STRING_TYPE : nativeType(constant.getType(), false)));
            } else if (expression instanceof VarExpr variable) {
                raw = resolveVariable(variable);
            } else if (expression instanceof ArithmeticExpr arithmetic) {
                raw = lowerArithmetic(arithmetic, output, location,
                        directId(requestedId, requestedType, nativeType(arithmetic.getType(), false)));
            } else if (expression instanceof NegationExpr negation) {
                raw = lowerNegation(negation, output, location,
                        directId(requestedId, requestedType, nativeType(negation.getType(), false)));
            } else if (expression instanceof CastExpr cast) {
                raw = lowerCast(cast, output, location,
                        directId(requestedId, requestedType, nativeType(cast.getType(), false)));
            } else if (expression instanceof ComparisonExpr comparison) {
                raw = lowerValueComparison(comparison, output, location,
                        directId(requestedId, requestedType, NativeType.Primitive.I32));
            } else if (expression instanceof FieldLoadExpr field) {
                raw = lowerFieldLoad(field, output, location,
                        directId(requestedId, requestedType, nativeType(field.getType(), false)));
            } else if (expression instanceof ArrayLoadExpr load) {
                raw = lowerArrayLoad(load, output, location,
                        directId(requestedId, requestedType, arrayComponentType(load)));
            } else if (expression instanceof ArrayLengthExpr length) {
                raw = lowerArrayLength(length, output, location,
                        directId(requestedId, requestedType, NativeType.Primitive.I32));
            } else if (expression instanceof NewArrayExpr array) {
                raw = lowerNewArray(array, output, location,
                        directId(requestedId, requestedType, nativeType(array.getType(), false)));
            } else if (expression instanceof InstanceofExpr instanceOf) {
                raw = lowerInstanceOf(instanceOf, output, location,
                        directId(requestedId, requestedType, NativeType.Primitive.I32));
            } else if (expression instanceof AllocObjectExpr allocation) {
                raw = lowerAllocation(allocation, output, location, requestedId, requestedType);
            } else if (expression instanceof InitialisedObjectExpr initialized) {
                raw = lowerInitializedObject(initialized, output, location, requestedId, requestedType);
            } else if (expression instanceof DynamicInvocationExpr dynamic) {
                raw = lowerDynamicCall(dynamic, output, location,
                        directId(requestedId, requestedType, nativeType(dynamic.getType(), false)));
            } else if (expression instanceof InvocationExpr invocation) {
                raw = lowerJavaCall(invocation, output, location,
                        directId(requestedId, requestedType, nativeType(invocation.getType(), false)));
            } else if (expression instanceof CaughtExceptionExpr caught) {
                final NativeType type = nativeType(caught.getType(), false);
                final String id = directId(requestedId, requestedType, type);
                final NativeInstruction.Operation operation = new NativeInstruction.Operation(
                        id == null ? temporary("caught") : id, type, NativeOpcode.CATCH_EXCEPTION,
                        List.of(), Map.of("type", caught.getType().getDescriptor()), location);
                semantic(output, operation);
                raw = new NativeOperand.Value(operation.id(), operation.type());
            } else if (expression instanceof PhiExpr) {
                throw failure(method, NativeLoweringException.Reason.UNSUPPORTED_EXPRESSION, expression,
                        "phi expressions must be the value of CopyPhiStmt");
            } else {
                throw failure(method, NativeLoweringException.Reason.UNSUPPORTED_EXPRESSION, expression,
                        "unsupported MapleIR expression " + expression.getClass().getName());
            }
            if (raw == null) {
                if (!requestedType.isVoid()) {
                    throw failure(method, NativeLoweringException.Reason.TYPE_MISMATCH, expression,
                            "void expression used where " + requestedType.displayName() + " is required");
                }
                return null;
            }
            return finish(expression, raw, output, location, requestedId, requestedType);
        }

        private NativeOperand lowerConstant(
                final ConstantExpr constant,
                final NativeBlock output,
                final SourceLocation location,
                final String directId
        ) {
            final Object value = constant.getConstant();
            if (value instanceof String string) {
                final NativeInstruction.Operation operation = new NativeInstruction.Operation(
                        directId == null ? temporary("string") : directId,
                        STRING_TYPE, NativeOpcode.STRING_CONSTANT, List.of(), Map.of("value", string), location);
                semantic(output, operation);
                return new NativeOperand.Value(operation.id(), operation.type());
            }
            if (value instanceof Type type) {
                final String descriptor = type.getSort() == Type.METHOD
                        ? "()Ljava/lang/invoke/MethodType;" : "()Ljava/lang/Class;";
                return dynamicConstant(output, location, directId, descriptor, "ldc.type",
                        Map.of("constant", encodeBootstrapArgument(type)), type);
            }
            if (value instanceof Handle handle) {
                return dynamicConstant(output, location, directId, "()Ljava/lang/invoke/MethodHandle;",
                        "ldc.handle", Map.of("constant", encodeBootstrapArgument(handle)), handle);
            }
            if (value instanceof ConstantDynamic dynamic) {
                final Map<String, String> attributes = new LinkedHashMap<>();
                attributes.put("name", dynamic.getName());
                try {
                    addBootstrapMetadata(attributes, dynamic.getBootstrapMethod(), bootstrapArguments(dynamic));
                } catch (final IllegalArgumentException exception) {
                    throw failure(method, NativeLoweringException.Reason.UNSUPPORTED_CONSTANT, constant,
                            exception.getMessage());
                }
                return dynamicConstant(output, location, directId, "()" + dynamic.getDescriptor(),
                        "ldc.constant-dynamic", attributes, dynamic);
            }
            return constantOperand(constant);
        }

        private NativeOperand dynamicConstant(
                final NativeBlock output,
                final SourceLocation location,
                final String directId,
                final String descriptor,
                final String bridge,
                final Map<String, String> extraAttributes,
                final Object constant
        ) {
            final NativeType type = JavaDescriptor.method(descriptor).returnType();
            final Map<String, String> attributes = new LinkedHashMap<>();
            attributes.put("bridge", bridge);
            attributes.put("descriptor", descriptor);
            attributes.putAll(extraAttributes);
            if (linkageBridges != null) {
                attributes.putAll(linkageBridges.constant(method, constant, descriptor).attributes());
            }
            final NativeInstruction.Operation operation = new NativeInstruction.Operation(
                    directId == null ? temporary("dynamic.constant") : directId,
                    type, NativeOpcode.DYNAMIC_BRIDGE, List.of(),
                    attributes, location);
            semantic(output, operation);
            return new NativeOperand.Value(operation.id(), operation.type());
        }

        private NativeOperand constantOperand(final ConstantExpr constant) {
            final NativeType type = localValueType(constant.getType());
            final Object value = constant.getConstant();
            if (value == null) {
                if (!type.isReferenceLike()) {
                    throw failure(method, NativeLoweringException.Reason.UNSUPPORTED_CONSTANT, constant,
                            "null constant has non-reference type " + constant.getType());
                }
                return new NativeOperand.Constant(type, null);
            }
            if (value instanceof Boolean bool) return new NativeOperand.Constant(type, bool);
            if (value instanceof Character character) return new NativeOperand.Constant(type, (int) character);
            if (value instanceof Number number) return new NativeOperand.Constant(type, number);
            throw failure(method, NativeLoweringException.Reason.UNSUPPORTED_CONSTANT, constant,
                    "unsupported constant " + value.getClass().getName());
        }

        private NativeOperand lowerArithmetic(
                final ArithmeticExpr arithmetic,
                final NativeBlock output,
                final SourceLocation location,
                final String directId
        ) {
            final NativeType resultType = nativeType(arithmetic.getType(), false);
            NativeOperand left = requireValue(arithmetic.getLeft(), lowerExpression(
                    arithmetic.getLeft(), output, location, null, resultType));
            final boolean shift = arithmetic.getOperator() == ArithmeticExpr.Operator.SHL
                    || arithmetic.getOperator() == ArithmeticExpr.Operator.SHR
                    || arithmetic.getOperator() == ArithmeticExpr.Operator.USHR;
            NativeOperand right = requireValue(arithmetic.getRight(), lowerExpression(
                    arithmetic.getRight(), output, location, null,
                    shift ? NativeType.Primitive.I32 : resultType));
            if (shift) {
                final int mask = resultType == NativeType.Primitive.I64 ? 63 : 31;
                final String maskId = temporary("shift.mask");
                output.addInstruction(new NativeInstruction.Operation(
                        maskId, NativeType.Primitive.I32, NativeOpcode.BIT_AND,
                        List.of(right, new NativeOperand.Constant(NativeType.Primitive.I32, mask)),
                        Map.of(), location));
                right = new NativeOperand.Value(maskId, NativeType.Primitive.I32);
            }
            final NativeOpcode opcode = arithmeticOpcode(arithmetic.getOperator(), resultType);
            if (opcode == NativeOpcode.SDIV || opcode == NativeOpcode.SREM) {
                // Java integer division can raise ArithmeticException and therefore needs the
                // same pending-exception routing context as JNI semantic operations.
                requiresSemanticContext = true;
            }
            final String id = directId == null ? temporary("arithmetic") : directId;
            output.addInstruction(new NativeInstruction.Operation(
                    id, resultType, opcode, List.of(left, right), Map.of(), location));
            return new NativeOperand.Value(id, resultType);
        }

        private NativeOperand lowerNegation(
                final NegationExpr negation,
                final NativeBlock output,
                final SourceLocation location,
                final String directId
        ) {
            final NativeType type = nativeType(negation.getType(), false);
            final NativeOperand operand = requireValue(negation.getExpression(), lowerExpression(
                    negation.getExpression(), output, location, null, type));
            final NativeOpcode opcode = type instanceof NativeType.Primitive primitive
                    && primitive.isFloatingPoint() ? NativeOpcode.FNEG : NativeOpcode.NEG;
            final String id = directId == null ? temporary("negate") : directId;
            output.addInstruction(new NativeInstruction.Operation(
                    id, type, opcode, List.of(operand), Map.of(), location));
            return new NativeOperand.Value(id, type);
        }

        private NativeOperand lowerCast(
                final CastExpr cast,
                final NativeBlock output,
                final SourceLocation location,
                final String directId
        ) {
            final NativeType target = nativeType(cast.getType(), false);
            final NativeOperand source = requireValue(cast.getExpression(), lowerExpression(
                    cast.getExpression(), output, location, null,
                    nativeType(cast.getExpression().getType(), false)));
            if (source.type().isReferenceLike() && target.isReferenceLike()) {
                final String id = directId == null ? temporary("check.cast") : directId;
                final NativeInstruction.Operation operation = new NativeInstruction.Operation(
                        id, target, NativeOpcode.CHECK_CAST, List.of(source),
                        Map.of("type", checkedTypeAttribute(cast.getType())), location);
                semantic(output, operation);
                return new NativeOperand.Value(operation.id(), operation.type());
            }
            return coerce(cast, source, target, output, location,
                    directId == null ? temporary("cast") : directId);
        }

        private NativeOperand lowerValueComparison(
                final ComparisonExpr comparison,
                final NativeBlock output,
                final SourceLocation location,
                final String directId
        ) {
            final Type commonAsm = TypeUtils.resolveBinOpType(
                    comparison.getLeft().getType(), comparison.getRight().getType());
            final NativeType common = nativeType(commonAsm, false);
            final NativeOperand left = requireValue(comparison.getLeft(), lowerExpression(
                    comparison.getLeft(), output, location, null, common));
            final NativeOperand right = requireValue(comparison.getRight(), lowerExpression(
                    comparison.getRight(), output, location, null, common));
            final String eqId = temporary("cmp.eq");
            output.addInstruction(new NativeInstruction.Operation(
                    eqId, NativeType.Primitive.I1,
                    common instanceof NativeType.Primitive primitive && primitive.isFloatingPoint()
                            ? NativeOpcode.FCMP_EQ : NativeOpcode.ICMP_EQ,
                    List.of(left, right), Map.of(), location));
            final NativeOperand eq = new NativeOperand.Value(eqId, NativeType.Primitive.I1);
            final NativeOperand zero = new NativeOperand.Constant(NativeType.Primitive.I32, 0);
            final NativeOperand minusOne = new NativeOperand.Constant(NativeType.Primitive.I32, -1);
            final NativeOperand plusOne = new NativeOperand.Constant(NativeType.Primitive.I32, 1);

            final String relationId = temporary("cmp.relation");
            final NativeOpcode relationOpcode;
            final NativeOperand relationTrue;
            final NativeOperand relationFalse;
            if (comparison.getComparisonType() == ComparisonExpr.ValueComparisonType.LT) {
                // FCMPL: NaN becomes -1, so test greater and use -1 as the fallback.
                relationOpcode = floating(common) ? NativeOpcode.FCMP_GT : NativeOpcode.ICMP_SGT;
                relationTrue = plusOne;
                relationFalse = minusOne;
            } else {
                // LCMP and FCMPG: test less; the fallback (+1) also handles FCMPG NaN.
                relationOpcode = floating(common) ? NativeOpcode.FCMP_LT : NativeOpcode.ICMP_SLT;
                relationTrue = minusOne;
                relationFalse = plusOne;
            }
            output.addInstruction(new NativeInstruction.Operation(
                    relationId, NativeType.Primitive.I1, relationOpcode,
                    List.of(left, right), Map.of(), location));
            final String nonEqualId = temporary("cmp.non-equal");
            output.addInstruction(new NativeInstruction.Operation(
                    nonEqualId, NativeType.Primitive.I32, NativeOpcode.SELECT,
                    List.of(new NativeOperand.Value(relationId, NativeType.Primitive.I1),
                            relationTrue, relationFalse), Map.of(), location));
            final String id = directId == null ? temporary("compare") : directId;
            output.addInstruction(new NativeInstruction.Operation(
                    id, NativeType.Primitive.I32, NativeOpcode.SELECT,
                    List.of(eq, zero, new NativeOperand.Value(nonEqualId, NativeType.Primitive.I32)),
                    Map.of(), location));
            return new NativeOperand.Value(id, NativeType.Primitive.I32);
        }

        private NativeOperand lowerFieldLoad(
                final FieldLoadExpr field,
                final NativeBlock output,
                final SourceLocation location,
                final String directId
        ) {
            final List<NativeOperand> operands = new ArrayList<>();
            if (!field.isStatic()) {
                operands.add(requireValue(field.getInstanceExpression(), lowerExpression(
                        field.getInstanceExpression(), output, location, null,
                        new NativeType.Reference(field.getOwner(), true))));
            }
            final NativeType type = nativeType(field.getType(), true);
            final NativeInstruction.Operation operation = new NativeInstruction.Operation(
                    directId == null ? temporary("field.get") : directId,
                    type, NativeOpcode.FIELD_GET, operands,
                    memberAttributes(field.getOwner(), field.getName(), field.getDesc(), field.isStatic()), location);
            semantic(output, operation);
            return new NativeOperand.Value(operation.id(), operation.type());
        }

        private NativeOperand lowerArrayLoad(
                final ArrayLoadExpr load,
                final NativeBlock output,
                final SourceLocation location,
                final String directId
        ) {
            final NativeOperand array = requireValue(load.getArrayExpression(), lowerExpression(
                    load.getArrayExpression(), output, location, null,
                    nativeType(load.getArrayExpression().getType(), false)));
            if (!(array.type() instanceof NativeType.Array arrayType)) {
                throw failure(method, NativeLoweringException.Reason.TYPE_MISMATCH, load,
                        "ARRAY_LOAD receiver is not an array");
            }
            final NativeOperand index = requireValue(load.getIndexExpression(), lowerExpression(
                    load.getIndexExpression(), output, location, null, NativeType.Primitive.I32));
            final NativeType result = arrayType.componentType();
            final NativeInstruction.Operation operation = new NativeInstruction.Operation(
                    directId == null ? temporary("array.load") : directId,
                    result, NativeOpcode.ARRAY_LOAD, List.of(array, index),
                    Map.of("descriptor", load.getArrayExpression().getType().getDescriptor()), location);
            semantic(output, operation);
            return new NativeOperand.Value(operation.id(), operation.type());
        }

        private NativeOperand lowerArrayLength(
                final ArrayLengthExpr length,
                final NativeBlock output,
                final SourceLocation location,
                final String directId
        ) {
            final NativeOperand array = requireValue(length.getExpression(), lowerExpression(
                    length.getExpression(), output, location, null,
                    nativeType(length.getExpression().getType(), false)));
            final NativeInstruction.Operation operation = new NativeInstruction.Operation(
                    directId == null ? temporary("array.length") : directId,
                    NativeType.Primitive.I32, NativeOpcode.ARRAY_LENGTH,
                    List.of(array), Map.of(), location);
            semantic(output, operation);
            return new NativeOperand.Value(operation.id(), operation.type());
        }

        private NativeOperand lowerNewArray(
                final NewArrayExpr array,
                final NativeBlock output,
                final SourceLocation location,
                final String directId
        ) {
            final NativeType type = nativeType(array.getType(), false);
            if (!(type instanceof NativeType.Array arrayType)) {
                throw failure(method, NativeLoweringException.Reason.TYPE_MISMATCH, array,
                        "NEW_ARRAY expression does not have an array type");
            }
            final List<NativeOperand> dimensions = new ArrayList<>();
            for (final Expr bound : array.getBounds()) {
                dimensions.add(requireValue(bound, lowerExpression(
                        bound, output, location, null, NativeType.Primitive.I32)));
            }
            final NativeInstruction.Operation operation = new NativeInstruction.Operation(
                    directId == null ? temporary("array.new") : directId,
                    type, NativeOpcode.ARRAY_NEW, dimensions,
                    Map.of("descriptor", array.getType().getDescriptor()), location);
            semantic(output, operation);
            final NativeOperand result = new NativeOperand.Value(operation.id(), operation.type());
            if (array.getCst().length > 0) {
                if (array.getBounds().length != 1) {
                    throw failure(method, NativeLoweringException.Reason.UNSUPPORTED_EXPRESSION, array,
                            "multidimensional array constants are not supported");
                }
                for (int index = 0; index < array.getCst().length; index++) {
                    final Expr item = array.getCst()[index];
                    final NativeOperand value = requireValue(item, lowerExpression(
                            item, output, location, null, arrayType.componentType()));
                    semantic(output, new NativeInstruction.Operation(
                            temporary("array.init"), NativeType.Primitive.VOID, NativeOpcode.ARRAY_STORE,
                            List.of(result, new NativeOperand.Constant(NativeType.Primitive.I32, index), value),
                            Map.of(), location));
                }
            }
            return result;
        }

        private NativeOperand lowerInstanceOf(
                final InstanceofExpr instanceOf,
                final NativeBlock output,
                final SourceLocation location,
                final String directId
        ) {
            final NativeOperand value = requireValue(instanceOf.getExpression(), lowerExpression(
                    instanceOf.getExpression(), output, location, null,
                    nativeType(instanceOf.getExpression().getType(), false)));
            final String boolId = temporary("instanceof.bool");
            semantic(output, new NativeInstruction.Operation(
                    boolId, NativeType.Primitive.I1, NativeOpcode.INSTANCE_OF, List.of(value),
                    Map.of("type", checkedTypeAttribute(instanceOf.getCheckType())), location));
            final String id = directId == null ? temporary("instanceof") : directId;
            output.addInstruction(new NativeInstruction.Operation(
                    id, NativeType.Primitive.I32, NativeOpcode.CONVERT,
                    List.of(new NativeOperand.Value(boolId, NativeType.Primitive.I1)),
                    Map.of("signed", "false"), location));
            return new NativeOperand.Value(id, NativeType.Primitive.I32);
        }

        private NativeOperand lowerAllocation(
                final AllocObjectExpr allocation,
                final NativeBlock output,
                final SourceLocation location,
                final String requestedId,
                final NativeType requestedType
        ) {
            final NativeType.Reference type = new NativeType.Reference(
                    allocation.getType().getInternalName(), false);
            final String direct = directId(requestedId, requestedType, type);
            final NativeInstruction.Operation operation = new NativeInstruction.Operation(
                    direct == null ? temporary("object.new") : direct,
                    type, NativeOpcode.NEW_OBJECT, List.of(),
                    Map.of("type", allocation.getType().getInternalName()), location);
            semantic(output, operation);
            return new NativeOperand.Value(operation.id(), operation.type());
        }

        private NativeOperand lowerInitializedObject(
                final InitialisedObjectExpr initialized,
                final NativeBlock output,
                final SourceLocation location,
                final String requestedId,
                final NativeType requestedType
        ) {
            final NativeType.Reference type = new NativeType.Reference(initialized.getOwner(), false);
            final String direct = directId(requestedId, requestedType, type);
            final NativeInstruction.Operation allocation = new NativeInstruction.Operation(
                    direct == null ? temporary("object.new") : direct,
                    type, NativeOpcode.NEW_OBJECT, List.of(),
                    Map.of("type", initialized.getOwner()), location);
            semantic(output, allocation);
            final NativeOperand object = new NativeOperand.Value(allocation.id(), allocation.type());
            final List<NativeOperand> operands = new ArrayList<>();
            operands.add(object);
            final Type[] parameterTypes = Type.getArgumentTypes(initialized.getDesc());
            final Expr[] arguments = initialized.getArgumentExprs();
            if (parameterTypes.length != arguments.length) {
                throw failure(method, NativeLoweringException.Reason.TYPE_MISMATCH, initialized,
                        "constructor operand count does not match descriptor");
            }
            for (int index = 0; index < arguments.length; index++) {
                operands.add(requireValue(arguments[index], lowerExpression(
                        arguments[index], output, location, null,
                        nativeType(parameterTypes[index], true))));
            }
            semantic(output, new NativeInstruction.Operation(
                    temporary("constructor"), NativeType.Primitive.VOID, NativeOpcode.JAVA_CALL,
                    operands, Map.of(
                            "owner", initialized.getOwner(),
                            "name", "<init>",
                            "descriptor", initialized.getDesc(),
                            "invoke", "special"
                    ), location));
            return object;
        }

        private NativeOperand lowerJavaCall(
                final InvocationExpr invocation,
                final NativeBlock output,
                final SourceLocation location,
                final String directId
        ) {
            final List<NativeOperand> operands = invocationOperands(invocation, output, location);
            final NativeType result = nativeType(invocation.getType(), true);
            if (linkageBridges != null) {
                final Optional<JavaLinkageBridgeRegistry.Bridge> bridge =
                        linkageBridges.callerSensitive(method, invocation);
                if (bridge.isPresent()) {
                    final NativeInstruction.Operation operation = new NativeInstruction.Operation(
                            directId == null ? temporary("dynamic.caller-sensitive") : directId,
                            result, NativeOpcode.DYNAMIC_BRIDGE, operands,
                            bridge.orElseThrow().attributes(), location);
                    semantic(output, operation);
                    return result.isVoid() ? null : new NativeOperand.Value(operation.id(), operation.type());
                }
            }
            final NativeInstruction.Operation operation = new NativeInstruction.Operation(
                    directId == null ? temporary("java.call") : directId,
                    result, NativeOpcode.JAVA_CALL, operands,
                    Map.of(
                            "owner", invocation.getOwner(),
                            "name", invocation.getName(),
                            "descriptor", invocation.getDesc(),
                            "invoke", invocation.getCallType().name().toLowerCase(Locale.ROOT)
                    ), location);
            semantic(output, operation);
            return result.isVoid() ? null : new NativeOperand.Value(operation.id(), operation.type());
        }

        private NativeOperand lowerDynamicCall(
                final DynamicInvocationExpr invocation,
                final NativeBlock output,
                final SourceLocation location,
                final String directId
        ) {
            final List<NativeOperand> operands = new ArrayList<>();
            final Type[] parameterTypes = Type.getArgumentTypes(invocation.getBootstrapDesc());
            final Expr[] arguments = invocation.getBoundArgs();
            if (parameterTypes.length != arguments.length) {
                throw failure(method, NativeLoweringException.Reason.TYPE_MISMATCH, invocation,
                        "invokedynamic operand count does not match its call-site descriptor");
            }
            for (int index = 0; index < arguments.length; index++) {
                operands.add(requireValue(arguments[index], lowerExpression(
                        arguments[index], output, location, null,
                        nativeType(parameterTypes[index], true))));
            }
            final NativeType result = nativeType(invocation.getType(), true);
            final Map<String, String> attributes = new LinkedHashMap<>();
            attributes.put("bridge", "invokedynamic");
            attributes.put("descriptor", invocation.getBootstrapDesc());
            attributes.put("name", invocation.getBoundName());
            try {
                addBootstrapMetadata(attributes, invocation.getBootstrapMethod(), invocation.getBootstrapArgs());
            } catch (final IllegalArgumentException exception) {
                throw failure(method, NativeLoweringException.Reason.UNSUPPORTED_CONSTANT, invocation,
                        exception.getMessage());
            }
            if (linkageBridges != null) {
                attributes.putAll(linkageBridges.invokedynamic(method, invocation).attributes());
            }
            final NativeInstruction.Operation operation = new NativeInstruction.Operation(
                    directId == null ? temporary("dynamic.call") : directId,
                    result, NativeOpcode.DYNAMIC_BRIDGE, operands, attributes, location);
            semantic(output, operation);
            return result.isVoid() ? null : new NativeOperand.Value(operation.id(), operation.type());
        }

        private List<NativeOperand> invocationOperands(
                final InvocationExpr invocation,
                final NativeBlock output,
                final SourceLocation location
        ) {
            final List<NativeOperand> operands = new ArrayList<>();
            final Expr[] arguments = invocation.getArgumentExprs();
            int expressionIndex = 0;
            if (!invocation.isStatic()) {
                if (arguments.length == 0) {
                    throw failure(method, NativeLoweringException.Reason.TYPE_MISMATCH, invocation,
                            "instance call has no receiver");
                }
                operands.add(requireValue(arguments[0], lowerExpression(
                        arguments[0], output, location, null,
                        new NativeType.Reference(invocation.getOwner(), true))));
                expressionIndex = 1;
            }
            final Type[] parameterTypes = Type.getArgumentTypes(invocation.getDesc());
            if (arguments.length - expressionIndex != parameterTypes.length) {
                throw failure(method, NativeLoweringException.Reason.TYPE_MISMATCH, invocation,
                        "call operand count does not match descriptor");
            }
            for (int index = 0; index < parameterTypes.length; index++) {
                final Expr argument = arguments[index + expressionIndex];
                operands.add(requireValue(argument, lowerExpression(
                        argument, output, location, null, nativeType(parameterTypes[index], true))));
            }
            return operands;
        }

        private NativeOperand finish(
                final Expr source,
                final NativeOperand operand,
                final NativeBlock output,
                final SourceLocation location,
                final String requestedId,
                final NativeType requestedType
        ) {
            NativeOperand result = operand;
            if (!result.type().equals(requestedType)) {
                result = coerce(source, result, requestedType, output, location,
                        requestedId == null ? temporary("coerce") : requestedId);
            } else if (requestedId != null
                    && (!(result instanceof NativeOperand.Value value) || !value.id().equals(requestedId))) {
                output.addInstruction(new NativeInstruction.Operation(
                        requestedId, requestedType, NativeOpcode.SELECT,
                        List.of(new NativeOperand.Constant(NativeType.Primitive.I1, true), result, result),
                        Map.of(), location));
                result = new NativeOperand.Value(requestedId, requestedType);
            }
            return result;
        }

        private NativeOperand coerce(
                final Expr source,
                final NativeOperand operand,
                final NativeType target,
                final NativeBlock output,
                final SourceLocation location,
                final String id
        ) {
            if (operand.type().equals(target)) return operand;
            final NativeInstruction.Operation operation;
            if (operand.type() instanceof NativeType.Primitive from
                    && target instanceof NativeType.Primitive to
                    && from.isNumeric() && to.isNumeric()) {
                final boolean signed = source.getType().getSort() != Type.CHAR
                        && source.getType().getSort() != Type.BOOLEAN;
                operation = new NativeInstruction.Operation(
                        id, target, NativeOpcode.CONVERT, List.of(operand),
                        Map.of("signed", Boolean.toString(signed)), location);
                output.addInstruction(operation);
            } else if (operand.type().isReferenceLike() && target.isReferenceLike()) {
                operation = new NativeInstruction.Operation(
                        id, target, NativeOpcode.REF_CAST, List.of(operand), Map.of(), location);
                output.addInstruction(operation);
            } else {
                throw failure(method, NativeLoweringException.Reason.TYPE_MISMATCH, source,
                        "cannot convert " + operand.type().displayName() + " to " + target.displayName());
            }
            return new NativeOperand.Value(operation.id(), operation.type());
        }

        private NativeOperand resolveVariable(final VarExpr variable) {
            final Definition definition = definitions.get(variable.getLocal());
            if (definition != null) return definition.value();
            if (!variable.getLocal().isStack()
                    && (!(variable.getLocal() instanceof VersionedLocal versioned)
                        || versioned.getSubscript() == 0)) {
                final ParameterBinding binding = parametersBySlot.get(variable.getLocal().getIndex());
                if (binding != null) {
                    return promotedParameters.getOrDefault(variable.getLocal().getIndex(),
                            new NativeOperand.Value(binding.parameter().id(), binding.parameter().type()));
                }
            }
            throw failure(method, NativeLoweringException.Reason.NON_SSA_LOCAL, variable,
                    "use of local " + variable.getLocal() + " has no SSA definition or parameter binding");
        }

        private Definition definition(final Local local, final Object node) {
            final Definition definition = definitions.get(local);
            if (definition == null) {
                throw failure(method, NativeLoweringException.Reason.NON_SSA_LOCAL, node,
                        "missing SSA definition for " + local);
            }
            return definition;
        }

        private void addExceptionEdges() {
            int priority = 0;
            for (final ExceptionRange<BasicBlock> range : cfg.getRanges()) {
                final List<Type> catchTypes = range.getTypes().stream()
                        .sorted(Comparator.comparing(Type::getDescriptor))
                        .toList();
                for (final BasicBlock protectedBlock : range.getNodes()) {
                    final NativeBlock output = nativeBlocks.get(protectedBlock);
                    if (output == null) continue;
                    if (!nativeBlocks.containsKey(range.getHandler())) {
                        throw failure(method, NativeLoweringException.Reason.INVALID_CONTROL_FLOW, range,
                                "exception range references a block outside the graph");
                    }
                    if (catchTypes.isEmpty()) {
                        output.addExceptionEdge(new NativeExceptionEdge(
                                blockId(range.getHandler()), Optional.empty(), priority));
                    } else {
                        for (int index = 0; index < catchTypes.size(); index++) {
                            output.addExceptionEdge(new NativeExceptionEdge(
                                    blockId(range.getHandler()),
                                    Optional.of(catchTypes.get(index).getInternalName()),
                                    priority + index));
                        }
                    }
                }
                priority += Math.max(1, catchTypes.size());
            }
        }

        private BasicBlock falseTarget(final BasicBlock block, final BasicBlock trueTarget) {
            final List<BasicBlock> successors = normalSuccessors(block);
            if (successors.size() == 1 && successors.get(0) == trueTarget) {
                return trueTarget;
            }
            final List<BasicBlock> candidates = successors.stream()
                    .filter(target -> target != trueTarget)
                    .toList();
            if (candidates.size() == 1) return candidates.get(0);
            final BasicBlock immediate = cfg.getImmediate(block);
            if (immediate != null && immediate != trueTarget) return immediate;
            throw failure(method, NativeLoweringException.Reason.INVALID_CONTROL_FLOW, block,
                    "conditional branch does not have exactly one false successor");
        }

        private List<BasicBlock> normalSuccessors(final BasicBlock block) {
            return cfg.getEdges(block).stream()
                    .filter(edge -> !(edge instanceof TryCatchEdge<?>))
                    .map(FlowEdge::dst)
                    .distinct()
                    .sorted(Comparator.comparingInt(BasicBlock::getNumericId))
                    .toList();
        }

        private NativeInstruction.Operation semantic(
                final NativeBlock output,
                final NativeInstruction.Operation operation
        ) {
            requiresSemanticContext = true;
            output.addInstruction(operation);
            return operation;
        }

        private SourceLocation location(final int sourceLine, final int statementIndex) {
            return new SourceLocation(sourceFile(method), sourceLine, statementIndex);
        }

        private String temporary(final String prefix) {
            return prefix.replace('.', '_') + "." + temporary++;
        }
    }

    private static NativeOpcode arithmeticOpcode(
            final ArithmeticExpr.Operator operator,
            final NativeType type
    ) {
        final boolean floating = floating(type);
        return switch (operator) {
            case ADD -> floating ? NativeOpcode.FADD : NativeOpcode.ADD;
            case SUB -> floating ? NativeOpcode.FSUB : NativeOpcode.SUB;
            case MUL -> floating ? NativeOpcode.FMUL : NativeOpcode.MUL;
            case DIV -> floating ? NativeOpcode.FDIV : NativeOpcode.SDIV;
            case REM -> floating ? NativeOpcode.FREM : NativeOpcode.SREM;
            case AND -> NativeOpcode.BIT_AND;
            case OR -> NativeOpcode.BIT_OR;
            case XOR -> NativeOpcode.BIT_XOR;
            case SHL -> NativeOpcode.SHL;
            case SHR -> NativeOpcode.ASHR;
            case USHR -> NativeOpcode.LSHR;
        };
    }

    private static NativeOpcode comparisonOpcode(
            final ConditionalJumpStmt.ComparisonType comparison,
            final NativeType type
    ) {
        final boolean floating = floating(type);
        return switch (comparison) {
            case EQ -> floating ? NativeOpcode.FCMP_EQ : NativeOpcode.ICMP_EQ;
            case NE -> floating ? NativeOpcode.FCMP_NE : NativeOpcode.ICMP_NE;
            case LT -> floating ? NativeOpcode.FCMP_LT : NativeOpcode.ICMP_SLT;
            case LE -> floating ? NativeOpcode.FCMP_LE : NativeOpcode.ICMP_SLE;
            case GT -> floating ? NativeOpcode.FCMP_GT : NativeOpcode.ICMP_SGT;
            case GE -> floating ? NativeOpcode.FCMP_GE : NativeOpcode.ICMP_SGE;
        };
    }

    private static boolean floating(final NativeType type) {
        return type instanceof NativeType.Primitive primitive && primitive.isFloatingPoint();
    }

    private static NativeType arrayComponentType(final ArrayLoadExpr load) {
        final NativeType array = nativeType(load.getArrayExpression().getType(), false);
        if (!(array instanceof NativeType.Array nativeArray)) {
            throw new IllegalArgumentException("Array load receiver does not have an array type");
        }
        return nativeArray.componentType();
    }

    private static NativeType localValueType(final Type type) {
        return type.getSort() >= Type.BOOLEAN && type.getSort() <= Type.INT
                ? NativeType.Primitive.I32 : nativeType(type, false);
    }

    private static NativeType nativeType(final Type type, final boolean boundary) {
        try {
            return switch (type.getSort()) {
                case Type.VOID -> NativeType.Primitive.VOID;
                case Type.BOOLEAN -> NativeType.Primitive.I1;
                case Type.BYTE -> NativeType.Primitive.I8;
                case Type.CHAR, Type.SHORT -> NativeType.Primitive.I16;
                case Type.INT -> NativeType.Primitive.I32;
                case Type.LONG -> NativeType.Primitive.I64;
                case Type.FLOAT -> NativeType.Primitive.F32;
                case Type.DOUBLE -> NativeType.Primitive.F64;
                case Type.OBJECT -> new NativeType.Reference(type.getInternalName(), true);
                case Type.ARRAY -> arrayType(type);
                default -> throw new IllegalArgumentException("unsupported ASM type " + type);
            };
        } catch (final RuntimeException exception) {
            throw new IllegalArgumentException("Cannot map JVM type " + type + " to native IR", exception);
        }
    }

    private static NativeType.Array arrayType(final Type type) {
        final Type component = Type.getType(type.getDescriptor().substring(1));
        return new NativeType.Array(nativeType(component, false), true);
    }

    private static String checkedTypeAttribute(final Type type) {
        return type.getSort() == Type.OBJECT ? type.getInternalName() : type.getDescriptor();
    }

    private static void addBootstrapMetadata(
            final Map<String, String> attributes,
            final Handle bootstrapMethod,
            final Object[] bootstrapArguments
    ) {
        attributes.put("bootstrap", encodeBootstrapArgument(bootstrapMethod));
        attributes.put("bootstrap.arg.count", Integer.toString(bootstrapArguments.length));
        for (int index = 0; index < bootstrapArguments.length; index++) {
            attributes.put("bootstrap.arg." + index,
                    encodeBootstrapArgument(bootstrapArguments[index]));
        }
    }

    private static Object[] bootstrapArguments(final ConstantDynamic dynamic) {
        final Object[] arguments = new Object[dynamic.getBootstrapMethodArgumentCount()];
        for (int index = 0; index < arguments.length; index++) {
            arguments[index] = dynamic.getBootstrapMethodArgument(index);
        }
        return arguments;
    }

    /**
     * Encodes JVM linkage constants without relying on ASM's diagnostic {@code toString()} format.
     * Each component is URL-safe base64, making the representation lossless and unambiguous for
     * generated Java bridge code and the native semantic runtime.
     */
    private static String encodeBootstrapArgument(final Object value) {
        if (value instanceof Integer integer) return "i:" + integer;
        if (value instanceof Long number) return "j:" + number;
        if (value instanceof Float number) {
            return "f:" + Integer.toUnsignedString(Float.floatToRawIntBits(number), 16);
        }
        if (value instanceof Double number) {
            return "d:" + Long.toUnsignedString(Double.doubleToRawLongBits(number), 16);
        }
        if (value instanceof String string) return "s:" + base64(string);
        if (value instanceof Type type) return "t:" + base64(type.getDescriptor());
        if (value instanceof Handle handle) {
            return "h:" + packed(
                    Integer.toString(handle.getTag()),
                    Boolean.toString(handle.isInterface()),
                    handle.getOwner(), handle.getName(), handle.getDesc());
        }
        if (value instanceof ConstantDynamic dynamic) {
            final List<String> parts = new ArrayList<>();
            parts.add(dynamic.getName());
            parts.add(dynamic.getDescriptor());
            parts.add(encodeBootstrapArgument(dynamic.getBootstrapMethod()));
            parts.add(Integer.toString(dynamic.getBootstrapMethodArgumentCount()));
            for (int index = 0; index < dynamic.getBootstrapMethodArgumentCount(); index++) {
                parts.add(encodeBootstrapArgument(dynamic.getBootstrapMethodArgument(index)));
            }
            return "c:" + packed(parts.toArray(String[]::new));
        }
        throw new IllegalArgumentException("Unsupported JVM bootstrap constant: "
                + (value == null ? "null" : value.getClass().getName()));
    }

    private static String packed(final String... components) {
        return java.util.Arrays.stream(components)
                .map(MapleNativeIrLowerer::base64)
                .collect(Collectors.joining("."));
    }

    private static String base64(final String value) {
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }

    private static String descriptor(final NativeType type) {
        if (type == NativeType.Primitive.I1) return "Z";
        if (type == NativeType.Primitive.I8) return "B";
        if (type == NativeType.Primitive.I16) return "S";
        if (type == NativeType.Primitive.I32) return "I";
        if (type == NativeType.Primitive.I64) return "J";
        if (type == NativeType.Primitive.F32) return "F";
        if (type == NativeType.Primitive.F64) return "D";
        if (type instanceof NativeType.Reference reference) return "L" + reference.internalName() + ";";
        if (type instanceof NativeType.Array array) return "[" + descriptor(array.componentType());
        throw new IllegalArgumentException("Cannot create descriptor for " + type.displayName());
    }

    private static Map<String, String> memberAttributes(
            final String owner,
            final String name,
            final String descriptor,
            final boolean statical
    ) {
        return Map.of(
                "owner", owner,
                "name", name,
                "descriptor", descriptor,
                "static", Boolean.toString(statical)
        );
    }

    private static String directId(
            final String requestedId,
            final NativeType requestedType,
            final NativeType operationType
    ) {
        return requestedId != null && requestedType.equals(operationType) ? requestedId : null;
    }

    private static NativeOperand requireValue(final Expr expression, final NativeOperand operand) {
        if (operand == null) {
            throw new IllegalArgumentException("Void expression used as a value: " + expression);
        }
        return operand;
    }

    private static boolean isMetadata(final Stmt stmt) {
        return stmt instanceof LineNumberStmt
                || stmt instanceof FrameStmt
                || stmt instanceof NopStmt
                || stmt instanceof SkidBogusStmt;
    }

    private static String blockId(final BasicBlock block) {
        return "b" + block.getNumericId();
    }

    private static String localId(final Local local) {
        final String kind = local.isStack() ? "s" : "l";
        final String version = local instanceof VersionedLocal versioned
                ? "." + versioned.getSubscript() : "";
        return kind + local.getIndex() + version;
    }

    private static String sourceFile(final MethodNode method) {
        final String source = method.owner.node.sourceFile;
        return source == null || source.isBlank() ? method.owner.getName() + ".java" : source;
    }

    private static String methodName(final MethodNode method) {
        return method.owner.getName() + "." + method.getName() + method.getDesc();
    }

    private static NativeLoweringException failure(
            final MethodNode method,
            final NativeLoweringException.Reason reason,
            final Object node,
            final String detail
    ) {
        final String nodeType = node == null ? "" : node.getClass().getSimpleName();
        return new NativeLoweringException(
                reason,
                methodName(method),
                nodeType,
                "Cannot lower " + methodName(method) + ": " + detail
        );
    }

    private record Definition(NativeOperand.Value value, AbstractCopyStmt statement, BasicBlock block) {
    }

    private record ParameterBinding(NativeParameter parameter, Type asmType) {
    }
}
