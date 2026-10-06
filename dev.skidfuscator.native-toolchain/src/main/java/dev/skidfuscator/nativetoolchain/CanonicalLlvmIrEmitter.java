package dev.skidfuscator.nativetoolchain;

import dev.skidfuscator.nativeir.NativeBlock;
import dev.skidfuscator.nativeir.NativeExceptionEdge;
import dev.skidfuscator.nativeir.JavaDescriptor;
import dev.skidfuscator.nativeir.NativeFunction;
import dev.skidfuscator.nativeir.NativeInstruction;
import dev.skidfuscator.nativeir.NativeIrVerifier;
import dev.skidfuscator.nativeir.NativeIrVerificationException;
import dev.skidfuscator.nativeir.NativeModule;
import dev.skidfuscator.nativeir.NativeOpcode;
import dev.skidfuscator.nativeir.NativeOperand;
import dev.skidfuscator.nativeir.NativeParameter;
import dev.skidfuscator.nativeir.NativeTerminator;
import dev.skidfuscator.nativeir.NativeType;
import dev.skidfuscator.nativeir.SourceLocation;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;

/**
 * Deterministically emits the target-neutral, pure subset of native IR as LLVM IR.
 *
 * <p>JVM references and arrays are opaque LLVM pointers. Java semantic operations use typed,
 * site-specific adapters plus canonical linkage metadata. Pending JNI exceptions are routed by
 * typed per-block dispatch sites, so Java catch edges never masquerade as LLVM unwinding.</p>
 */
public final class CanonicalLlvmIrEmitter implements LlvmIrEmitter {
    private static final Set<NativeOpcode> SEMANTIC_OPCODES = Set.of(
            NativeOpcode.JAVA_CALL,
            NativeOpcode.DYNAMIC_BRIDGE,
            NativeOpcode.FIELD_GET,
            NativeOpcode.FIELD_SET,
            NativeOpcode.NEW_OBJECT,
            NativeOpcode.INSTANCE_OF,
            NativeOpcode.CHECK_CAST,
            NativeOpcode.ARRAY_NEW,
            NativeOpcode.ARRAY_LENGTH,
            NativeOpcode.ARRAY_LOAD,
            NativeOpcode.ARRAY_STORE,
            NativeOpcode.MONITOR_ENTER,
            NativeOpcode.MONITOR_EXIT,
            NativeOpcode.CATCH_EXCEPTION
    );

    private static final List<String> SEMANTIC_HELPERS = List.of(
            "array_length",
            "array_load",
            "array_new",
            "array_store",
            "check_cast",
            "dynamic_bridge",
            "field_get",
            "field_set",
            "instance_of",
            "java_call",
            "monitor_enter",
            "monitor_exit",
            "new_object",
            "throw"
    );

    private final NativeIrVerifier verifier;
    private final NativeStringProtection stringProtection;

    public CanonicalLlvmIrEmitter() {
        this(new NativeIrVerifier(), null);
    }

    /** Creates an emitter whose string payloads are diversified for one protected build. */
    public CanonicalLlvmIrEmitter(final NativeStringProtection stringProtection) {
        this(new NativeIrVerifier(), Objects.requireNonNull(stringProtection, "stringProtection"));
    }

    CanonicalLlvmIrEmitter(final NativeIrVerifier verifier) {
        this(verifier, null);
    }

    CanonicalLlvmIrEmitter(
            final NativeIrVerifier verifier,
            final NativeStringProtection stringProtection
    ) {
        this.verifier = Objects.requireNonNull(verifier, "verifier");
        this.stringProtection = stringProtection;
    }

    @Override
    public byte[] emit(final NativeModule module) {
        Objects.requireNonNull(module, "module");
        try {
            verifier.verifyOrThrow(module);
        } catch (NativeIrVerificationException exception) {
            throw new LlvmEmissionException(exception.getMessage(), exception);
        }

        final List<NativeFunction> functions = module.functions().stream()
                .sorted(Comparator.comparing(NativeFunction::symbol))
                .toList();
        final StringConstants stringConstants = new StringConstants(functions, stringProtection);
        final SemanticSites semanticSites = new SemanticSites(functions);

        final StringBuilder output = new StringBuilder(4096);
        output.append("; Skidfuscator canonical LLVM IR\n")
                .append("; native-ir-abi = ").append(module.abiVersion()).append('\n')
                .append("source_filename = \"").append(escapedBytes(module.name())).append("\"\n\n")
                .append("; Semantic helper ABI v1: (context, request, result) -> status.\n")
                .append("; Typed site adapters and exception routing are described by !skid.semantic.sites.\n");
        for (final String helper : SEMANTIC_HELPERS) {
            output.append("declare i32 @\"")
                    .append("skid.semantic.").append(helper).append(".v1")
                    .append("\"(ptr, ptr, ptr)\n");
        }
        output.append("declare i32 @\"skid.semantic.reference_equals.v1\"(ptr, ptr, ptr)\n");
        output.append(stringConstants.helperDeclaration());
        stringConstants.emitGlobals(output);
        semanticSites.emitDeclarations(output);

        final Metadata metadata = new Metadata(module, functions);
        semanticSites.addMetadata(metadata);
        for (final NativeFunction function : functions) {
            output.append('\n');
            emitFunction(function, output, metadata, stringConstants, semanticSites);
        }
        metadata.emit(output);
        return output.toString().getBytes(StandardCharsets.UTF_8);
    }

    private void emitFunction(
            final NativeFunction function,
            final StringBuilder output,
            final Metadata metadata,
            final StringConstants stringConstants,
            final SemanticSites semanticSites
    ) {
        validateFunctionBoundary(function);
        final List<NativeParameter> parameters = orderedParameters(function);
        final List<NativeBlock> blocks = orderedBlocks(function);
        rejectEntryPredecessors(function, blocks);
        final ControlFlowLayout layout = new ControlFlowLayout(function, blocks);

        output.append("define hidden ").append(type(function.returnType()))
                .append(" @\"").append(escapedBytes(function.symbol())).append("\"(");
        boolean hasParameter = false;
        if (function.requiresSemanticContext()) {
            output.append("ptr ").append(semanticContextName());
            hasParameter = true;
        }
        for (int index = 0; index < parameters.size(); index++) {
            if (hasParameter) {
                output.append(", ");
            }
            final NativeParameter parameter = parameters.get(index);
            output.append(type(parameter.type())).append(' ').append(valueName(parameter.id()));
            hasParameter = true;
        }
        output.append(") {\n");

        final Map<String, NativeOperand> aliases = collectAliases(function);
        for (final NativeBlock block : blocks) {
            output.append(blockName(block.id())).append(":\n");
            int dispatchIndex = 0;
            for (final NativeInstruction instruction : block.instructions()) {
                metadata.addSource(function, block, instruction.id(), instruction.sourceLocation());
                if (instruction instanceof NativeInstruction.Phi phi) {
                    emitPhi(function, block, phi, aliases, output, layout);
                } else {
                    dispatchIndex = emitOperation(function, block,
                            (NativeInstruction.Operation) instruction, aliases, output,
                            stringConstants, semanticSites, layout, dispatchIndex);
                }
            }
            final NativeTerminator terminator = block.terminator().orElseThrow();
            metadata.addSource(function, block, "<terminator>", terminator.sourceLocation());
            emitTerminator(function, block, terminator, aliases, output, semanticSites, layout, dispatchIndex);
        }
        if (layout.hasExceptionDispatch()) {
            output.append(layout.exceptionEscapeLabel()).append(":\n  ret ")
                    .append(type(function.returnType()));
            if (!function.returnType().isVoid()) {
                output.append(' ').append(zeroValue(function.returnType()));
            }
            output.append('\n');
        }
        output.append("}\n");
    }

    private void validateFunctionBoundary(final NativeFunction function) {
        if (function.returnType().isReferenceLike()) {
            // Supported as an opaque JNI reference. This test documents the intentional mapping.
            type(function.returnType());
        }
    }

    private Map<String, NativeOperand> collectAliases(final NativeFunction function) {
        final Map<String, NativeOperand> aliases = new HashMap<>();
        for (final NativeBlock block : function.blocks()) {
            for (final NativeInstruction instruction : block.instructions()) {
                if (instruction instanceof NativeInstruction.Operation operation
                        && ((operation.opcode() == NativeOpcode.CONVERT
                                && operation.type().equals(operation.operands().get(0).type()))
                            || operation.opcode() == NativeOpcode.REF_CAST)) {
                    validateAttributes(function, operation);
                    aliases.put(operation.id(), operation.operands().get(0));
                }
            }
        }
        return aliases;
    }

    private List<NativeParameter> orderedParameters(final NativeFunction function) {
        final List<NativeParameter> parameters = function.parameters().stream()
                .sorted(Comparator.comparingInt(NativeParameter::index))
                .toList();
        for (int index = 0; index < parameters.size(); index++) {
            if (parameters.get(index).index() != index) {
                throw unsupported(function, "non-contiguous parameter indexes; expected " + index
                        + " but found " + parameters.get(index).index());
            }
        }
        return parameters;
    }

    private List<NativeBlock> orderedBlocks(final NativeFunction function) {
        final Map<String, NativeBlock> byId = new HashMap<>();
        function.blocks().forEach(block -> byId.put(block.id(), block));
        final List<NativeBlock> ordered = new ArrayList<>();
        ordered.add(byId.get(function.entryBlock()));
        function.blocks().stream()
                .filter(block -> !block.id().equals(function.entryBlock()))
                .sorted(Comparator.comparing(NativeBlock::id))
                .forEach(ordered::add);
        return ordered;
    }

    private void rejectEntryPredecessors(final NativeFunction function, final List<NativeBlock> blocks) {
        for (final NativeBlock block : blocks) {
            if (block.terminator().orElseThrow().successors().contains(function.entryBlock())
                    || block.exceptionEdges().stream()
                    .anyMatch(edge -> edge.handlerBlock().equals(function.entryBlock()))) {
                throw unsupported(function, "a control-flow edge targeting the LLVM entry block");
            }
        }
    }

    private void emitPhi(
            final NativeFunction function,
            final NativeBlock block,
            final NativeInstruction.Phi phi,
            final Map<String, NativeOperand> aliases,
            final StringBuilder output,
            final ControlFlowLayout layout
    ) {
        output.append("  ").append(valueName(phi.id())).append(" = phi ").append(type(phi.type())).append(' ');
        final List<NativeInstruction.Phi.Incoming> incoming = phi.incoming().stream()
                .sorted(Comparator.comparing(NativeInstruction.Phi.Incoming::predecessorBlock))
                .toList();
        boolean emitted = false;
        for (final NativeInstruction.Phi.Incoming item : incoming) {
            for (final String concretePredecessor
                    : layout.predecessors(function, resolveAlias(item.value(), aliases),
                            item.predecessorBlock(), block.id())) {
                if (emitted) output.append(", ");
                emitted = true;
                output.append("[ ").append(operand(function, item.value(), aliases))
                        .append(", %").append(concretePredecessor).append(" ]");
            }
        }
        if (!emitted) {
            throw unsupported(function, "phi " + phi.id() + " has no concrete LLVM predecessors");
        }
        output.append('\n');
    }

    private int emitOperation(
            final NativeFunction function,
            final NativeBlock block,
            final NativeInstruction.Operation operation,
            final Map<String, NativeOperand> aliases,
            final StringBuilder output,
            final StringConstants stringConstants,
            final SemanticSites semanticSites,
            final ControlFlowLayout layout,
            final int dispatchIndex
    ) {
        if (SEMANTIC_OPCODES.contains(operation.opcode())) {
            emitSemanticOperation(function, operation, aliases, output, semanticSites);
            emitExceptionDispatch(function, block, output, semanticSites, layout, dispatchIndex, true);
            return dispatchIndex + 1;
        }
        if (operation.opcode() == NativeOpcode.SDIV
                || operation.opcode() == NativeOpcode.UDIV
                || operation.opcode() == NativeOpcode.SREM
                || operation.opcode() == NativeOpcode.UREM) {
            emitJavaIntegerDivision(function, block, operation, aliases, output,
                    semanticSites, layout, dispatchIndex);
            return dispatchIndex + 1;
        }
        validateAttributes(function, operation);
        if ((operation.opcode() == NativeOpcode.CONVERT
                && operation.type().equals(operation.operands().get(0).type()))
                || operation.opcode() == NativeOpcode.REF_CAST) {
            return dispatchIndex;
        }
        if (operation.opcode() == NativeOpcode.CONVERT
                && ((NativeType.Primitive) operation.operands().get(0).type()).isFloatingPoint()
                && ((NativeType.Primitive) operation.type()).isInteger()) {
            emitJavaFloatingToInteger(function, operation, aliases, output);
            return dispatchIndex;
        }

        if (operation.opcode() == NativeOpcode.SHL || operation.opcode() == NativeOpcode.ASHR
                || operation.opcode() == NativeOpcode.LSHR) {
            emitShift(function, operation, aliases, output);
            return dispatchIndex;
        }
        if ((operation.opcode() == NativeOpcode.ICMP_EQ || operation.opcode() == NativeOpcode.ICMP_NE)
                && operation.operands().get(0).type().isReferenceLike()) {
            if (!function.requiresSemanticContext()) throw unsupported(function, "reference equality without JNI context");
            final String status = valueName(operation.id() + ".reference.identity");
            output.append("  ").append(status)
                    .append(" = call i32 @\"skid.semantic.reference_equals.v1\"(ptr ")
                    .append(semanticContextName()).append(", ")
                    .append(typedOperand(function, operation.operands().get(0), aliases)).append(", ")
                    .append(typedOperand(function, operation.operands().get(1), aliases)).append(")\n");
            output.append("  ").append(valueName(operation.id())).append(" = icmp ")
                    .append(operation.opcode() == NativeOpcode.ICMP_EQ ? "ne" : "eq")
                    .append(" i32 ").append(status).append(", 0\n");
            return dispatchIndex;
        }
        output.append("  ").append(valueName(operation.id())).append(" = ");
        final List<NativeOperand> operands = operation.operands();
        switch (operation.opcode()) {
            case ADD, SUB, MUL, SDIV, UDIV, SREM, UREM, FADD, FSUB, FMUL, FDIV, FREM,
                    BIT_AND, BIT_OR, BIT_XOR, SHL, ASHR, LSHR ->
                    emitBinary(function, operation, aliases, output);
            case NEG -> output.append("sub ").append(type(operation.type())).append(" 0, ")
                    .append(operand(function, operands.get(0), aliases));
            case FNEG -> output.append("fneg ").append(type(operation.type())).append(' ')
                    .append(operand(function, operands.get(0), aliases));
            case BIT_NOT -> output.append("xor ").append(type(operation.type())).append(' ')
                    .append(operand(function, operands.get(0), aliases)).append(", ")
                    .append(operation.type() == NativeType.Primitive.I1 ? "true" : "-1");
            case ICMP_EQ, ICMP_NE, ICMP_SLT, ICMP_SLE, ICMP_SGT, ICMP_SGE ->
                    emitIntegerComparison(function, operation, aliases, output);
            case FCMP_EQ, FCMP_NE, FCMP_LT, FCMP_LE, FCMP_GT, FCMP_GE ->
                    emitFloatingComparison(function, operation, aliases, output);
            case SELECT -> output.append("select i1 ")
                    .append(operand(function, operands.get(0), aliases)).append(", ")
                    .append(typedOperand(function, operands.get(1), aliases)).append(", ")
                    .append(typedOperand(function, operands.get(2), aliases));
            case CONVERT -> emitConversion(function, operation, aliases, output);
            case STRING_CONSTANT -> emitStringConstant(function, operation, output, stringConstants);
            default -> throw unsupported(function, "operation " + operation.opcode());
        }
        output.append('\n');
        if (operation.opcode() == NativeOpcode.STRING_CONSTANT) {
            emitExceptionDispatch(function, block, output, semanticSites, layout, dispatchIndex, true);
            return dispatchIndex + 1;
        }
        return dispatchIndex;
    }

    private void emitSemanticOperation(
            final NativeFunction function,
            final NativeInstruction.Operation operation,
            final Map<String, NativeOperand> aliases,
            final StringBuilder output,
            final SemanticSites semanticSites
    ) {
        if (!function.requiresSemanticContext()) {
            throw unsupported(function, operation.opcode() + " without a semantic context");
        }
        output.append("  ");
        if (!operation.type().isVoid()) {
            output.append(valueName(operation.id())).append(" = ");
        }
        output.append("call ").append(type(operation.type())).append(" @\"")
                .append(escapedBytes(semanticSites.operationSymbol(function, operation)))
                .append("\"(ptr ").append(semanticContextName());
        for (final NativeOperand operand : operation.operands()) {
            output.append(", ").append(typedOperand(function, operand, aliases));
        }
        output.append(")\n");
    }

    private void emitJavaIntegerDivision(
            final NativeFunction function,
            final NativeBlock block,
            final NativeInstruction.Operation operation,
            final Map<String, NativeOperand> aliases,
            final StringBuilder output,
            final SemanticSites semanticSites,
            final ControlFlowLayout layout,
            final int dispatchIndex
    ) {
        if (!function.requiresSemanticContext()) {
            throw unsupported(function, operation.opcode()
                    + " requires a semantic context for Java divide-by-zero behavior");
        }
        validateAttributes(function, operation);
        final NativeType.Primitive integerType = (NativeType.Primitive) operation.type();
        final String left = operand(function, operation.operands().get(0), aliases);
        final String right = operand(function, operation.operands().get(1), aliases);
        final String zero = valueName(operation.id() + ".skid.zero");
        output.append("  ").append(zero).append(" = icmp eq ").append(type(integerType))
                .append(' ').append(right).append(", 0\n")
                .append("  call void @\"")
                .append(escapedBytes(semanticSites.divideGuardSymbol(function, operation)))
                .append("\"(ptr ").append(semanticContextName()).append(", ")
                .append(type(integerType)).append(' ').append(left).append(", ")
                .append(type(integerType)).append(' ').append(right).append(")\n");
        emitExceptionDispatch(function, block, output, semanticSites, layout, dispatchIndex, true);

        final boolean signed = operation.opcode() == NativeOpcode.SDIV
                || operation.opcode() == NativeOpcode.SREM;
        String unsafe = zero;
        String overflow = null;
        if (signed) {
            final BigInteger minimum = BigInteger.ONE.shiftLeft(integerType.bits() - 1).negate();
            final String isMinimum = valueName(operation.id() + ".skid.minimum");
            final String isNegativeOne = valueName(operation.id() + ".skid.negative-one");
            overflow = valueName(operation.id() + ".skid.overflow");
            final String invalid = valueName(operation.id() + ".skid.invalid");
            output.append("  ").append(isMinimum).append(" = icmp eq ")
                    .append(type(integerType)).append(' ').append(left).append(", ").append(minimum).append('\n')
                    .append("  ").append(isNegativeOne).append(" = icmp eq ")
                    .append(type(integerType)).append(' ').append(right).append(", -1\n")
                    .append("  ").append(overflow).append(" = and i1 ")
                    .append(isMinimum).append(", ").append(isNegativeOne).append('\n')
                    .append("  ").append(invalid).append(" = or i1 ")
                    .append(zero).append(", ").append(overflow).append('\n');
            unsafe = invalid;
        }
        final String safeDivisor = valueName(operation.id() + ".skid.safe-divisor");
        final String raw = valueName(operation.id() + ".skid.raw");
        output.append("  ").append(safeDivisor).append(" = select i1 ").append(unsafe)
                .append(", ").append(type(integerType)).append(" 1, ")
                .append(type(integerType)).append(' ').append(right).append('\n')
                .append("  ").append(raw).append(" = ")
                .append(operation.opcode().name().toLowerCase(java.util.Locale.ROOT)).append(' ')
                .append(type(integerType)).append(' ').append(left).append(", ").append(safeDivisor).append('\n');
        if (signed && operation.opcode() == NativeOpcode.SDIV) {
            final BigInteger minimum = BigInteger.ONE.shiftLeft(integerType.bits() - 1).negate();
            output.append("  ").append(valueName(operation.id())).append(" = select i1 ")
                    .append(overflow).append(", ").append(type(integerType)).append(' ').append(minimum)
                    .append(", ").append(type(integerType)).append(' ').append(raw).append('\n');
        } else if (signed && operation.opcode() == NativeOpcode.SREM) {
            output.append("  ").append(valueName(operation.id())).append(" = select i1 ")
                    .append(overflow).append(", ").append(type(integerType)).append(" 0, ")
                    .append(type(integerType)).append(' ').append(raw).append('\n');
        } else {
            output.append("  ").append(valueName(operation.id())).append(" = add ")
                    .append(type(integerType)).append(" 0, ").append(raw).append('\n');
        }
    }

    private void emitJavaFloatingToInteger(
            final NativeFunction function,
            final NativeInstruction.Operation operation,
            final Map<String, NativeOperand> aliases,
            final StringBuilder output
    ) {
        validateAttributes(function, operation);
        final NativeType.Primitive source = (NativeType.Primitive) operation.operands().get(0).type();
        final NativeType.Primitive target = (NativeType.Primitive) operation.type();
        if (target != NativeType.Primitive.I32 && target != NativeType.Primitive.I64) {
            throw unsupported(function, "direct floating-to-" + target.displayName()
                    + " conversion; JVM narrowing must first convert to i32 and then truncate");
        }
        final boolean signed = signedConversion(function, operation, source);
        final String value = operand(function, operation.operands().get(0), aliases);
        final String nan = valueName(operation.id() + ".skid.nan");
        final String low = valueName(operation.id() + ".skid.low");
        final String high = valueName(operation.id() + ".skid.high");
        final String unsafeLow = valueName(operation.id() + ".skid.unsafe-low");
        final String unsafe = valueName(operation.id() + ".skid.unsafe");
        final String safe = valueName(operation.id() + ".skid.safe");
        final String raw = valueName(operation.id() + ".skid.raw");
        final String lowResult = valueName(operation.id() + ".skid.low-result");
        final String bounded = valueName(operation.id() + ".skid.bounded");

        final BigInteger minimum = signed
                ? BigInteger.ONE.shiftLeft(target.bits() - 1).negate()
                : BigInteger.ZERO;
        final BigInteger maximum = signed
                ? BigInteger.ONE.shiftLeft(target.bits() - 1).subtract(BigInteger.ONE)
                : BigInteger.ONE.shiftLeft(target.bits()).subtract(BigInteger.ONE);
        final double lowerBoundary = signed ? -Math.scalb(1.0d, target.bits() - 1) : 0.0d;
        final double upperBoundary = Math.scalb(1.0d, signed ? target.bits() - 1 : target.bits());
        final String floatingZero = floatingConstant(function, source, 0.0d);
        output.append("  ").append(nan).append(" = fcmp uno ").append(type(source)).append(' ')
                .append(value).append(", ").append(value).append('\n')
                .append("  ").append(low).append(" = fcmp ").append(signed ? "ole" : "olt").append(' ')
                .append(type(source)).append(' ').append(value).append(", ")
                .append(floatingConstant(function, source, lowerBoundary)).append('\n')
                .append("  ").append(high).append(" = fcmp oge ").append(type(source)).append(' ')
                .append(value).append(", ")
                .append(floatingConstant(function, source, upperBoundary)).append('\n')
                .append("  ").append(unsafeLow).append(" = or i1 ").append(nan).append(", ").append(low).append('\n')
                .append("  ").append(unsafe).append(" = or i1 ").append(unsafeLow).append(", ").append(high).append('\n')
                .append("  ").append(safe).append(" = select i1 ").append(unsafe).append(", ")
                .append(type(source)).append(' ').append(floatingZero).append(", ")
                .append(type(source)).append(' ').append(value).append('\n')
                .append("  ").append(raw).append(" = ").append(signed ? "fptosi" : "fptoui").append(' ')
                .append(type(source)).append(' ').append(safe).append(" to ").append(type(target)).append('\n')
                .append("  ").append(lowResult).append(" = select i1 ").append(low).append(", ")
                .append(type(target)).append(' ').append(minimum).append(", ")
                .append(type(target)).append(' ').append(raw).append('\n')
                .append("  ").append(bounded).append(" = select i1 ").append(high).append(", ")
                .append(type(target)).append(' ').append(maximum).append(", ")
                .append(type(target)).append(' ').append(lowResult).append('\n')
                .append("  ").append(valueName(operation.id())).append(" = select i1 ").append(nan).append(", ")
                .append(type(target)).append(" 0, ").append(type(target)).append(' ').append(bounded).append('\n');
    }

    private void emitExceptionDispatch(
            final NativeFunction function,
            final NativeBlock block,
            final StringBuilder output,
            final SemanticSites semanticSites,
            final ControlFlowLayout layout,
            final int dispatchIndex,
            final boolean continueWhenClear
    ) {
        if (!function.requiresSemanticContext()) {
            throw unsupported(function, "exception dispatch without a semantic context");
        }
        final String status = valueName("skid.exception.status." + block.id() + "." + dispatchIndex);
        output.append("  ").append(status).append(" = call i32 @\"")
                .append(escapedBytes(semanticSites.exceptionDispatchSymbol(function, block)))
                .append("\"(ptr ").append(semanticContextName()).append(")\n")
                .append("  switch i32 ").append(status).append(", label %")
                .append(layout.exceptionEscapeLabel()).append(" [\n");
        if (continueWhenClear) {
            output.append("    i32 -1, label %").append(layout.continuationLabel(block, dispatchIndex + 1))
                    .append('\n');
        }
        final List<NativeExceptionEdge> edges = orderedExceptionEdges(block);
        for (int index = 0; index < edges.size(); index++) {
            output.append("    i32 ").append(index).append(", label %")
                    .append(blockName(edges.get(index).handlerBlock())).append('\n');
        }
        output.append("  ]\n");
        if (continueWhenClear) {
            output.append(layout.continuationLabel(block, dispatchIndex + 1)).append(":\n");
        }
    }

    private List<NativeExceptionEdge> orderedExceptionEdges(final NativeBlock block) {
        return block.exceptionEdges().stream()
                .sorted(Comparator.comparingInt(NativeExceptionEdge::priority)
                        .thenComparing(edge -> edge.catchType().orElse(""))
                        .thenComparing(NativeExceptionEdge::handlerBlock))
                .toList();
    }

    private void emitStringConstant(
            final NativeFunction function,
            final NativeInstruction.Operation operation,
            final StringBuilder output,
            final StringConstants stringConstants
    ) {
        if (!function.requiresSemanticContext()) {
            throw unsupported(function, "STRING_CONSTANT without a semantic context");
        }
        final String value = operation.attributes().get("value");
        stringConstants.emitCall(value, semanticContextName(), output);
    }

    private void emitShift(final NativeFunction function, final NativeInstruction.Operation operation,
                           final Map<String, NativeOperand> aliases, final StringBuilder output) {
        final NativeOperand amount = operation.operands().get(1);
        final NativeType.Primitive resultType = (NativeType.Primitive) operation.type();
        final NativeType.Primitive amountType = (NativeType.Primitive) amount.type();
        final String masked = valueName(operation.id() + ".shift.mask");
        output.append("  ").append(masked).append(" = and ").append(type(amount.type())).append(' ')
                .append(operand(function, amount, aliases)).append(", ").append(resultType.bits() - 1).append('\n');
        String distance = masked;
        if (amountType.bits() != resultType.bits()) {
            distance = valueName(operation.id() + ".shift.width");
            output.append("  ").append(distance).append(" = ")
                    .append(amountType.bits() < resultType.bits() ? "zext " : "trunc ")
                    .append(type(amount.type())).append(' ').append(masked).append(" to ")
                    .append(type(resultType)).append('\n');
        }
        output.append("  ").append(valueName(operation.id())).append(" = ")
                .append(operation.opcode().name().toLowerCase(java.util.Locale.ROOT)).append(' ')
                .append(type(resultType)).append(' ')
                .append(operand(function, operation.operands().get(0), aliases))
                .append(", ").append(distance).append('\n');
    }

    private void emitBinary(
            final NativeFunction function,
            final NativeInstruction.Operation operation,
            final Map<String, NativeOperand> aliases,
            final StringBuilder output
    ) {
        final String llvmOpcode = switch (operation.opcode()) {
            case BIT_AND -> "and";
            case BIT_OR -> "or";
            case BIT_XOR -> "xor";
            case SHL -> "shl";
            case ASHR -> "ashr";
            case LSHR -> "lshr";
            default -> operation.opcode().name().toLowerCase(java.util.Locale.ROOT);
        };
        output.append(llvmOpcode).append(' ')
                .append(type(operation.type())).append(' ')
                .append(operand(function, operation.operands().get(0), aliases)).append(", ")
                .append(operand(function, operation.operands().get(1), aliases));
    }

    private void emitIntegerComparison(
            final NativeFunction function,
            final NativeInstruction.Operation operation,
            final Map<String, NativeOperand> aliases,
            final StringBuilder output
    ) {
        final String predicate = switch (operation.opcode()) {
            case ICMP_EQ -> "eq";
            case ICMP_NE -> "ne";
            case ICMP_SLT -> "slt";
            case ICMP_SLE -> "sle";
            case ICMP_SGT -> "sgt";
            case ICMP_SGE -> "sge";
            default -> throw new AssertionError(operation.opcode());
        };
        output.append("icmp ").append(predicate).append(' ')
                .append(type(operation.operands().get(0).type())).append(' ')
                .append(operand(function, operation.operands().get(0), aliases)).append(", ")
                .append(operand(function, operation.operands().get(1), aliases));
    }

    private void emitFloatingComparison(
            final NativeFunction function,
            final NativeInstruction.Operation operation,
            final Map<String, NativeOperand> aliases,
            final StringBuilder output
    ) {
        final String predicate = switch (operation.opcode()) {
            case FCMP_EQ -> "oeq";
            case FCMP_NE -> "une";
            case FCMP_LT -> "olt";
            case FCMP_LE -> "ole";
            case FCMP_GT -> "ogt";
            case FCMP_GE -> "oge";
            default -> throw new AssertionError(operation.opcode());
        };
        output.append("fcmp ").append(predicate).append(' ')
                .append(type(operation.operands().get(0).type())).append(' ')
                .append(operand(function, operation.operands().get(0), aliases)).append(", ")
                .append(operand(function, operation.operands().get(1), aliases));
    }

    private void emitConversion(
            final NativeFunction function,
            final NativeInstruction.Operation operation,
            final Map<String, NativeOperand> aliases,
            final StringBuilder output
    ) {
        final NativeType.Primitive source = (NativeType.Primitive) operation.operands().get(0).type();
        final NativeType.Primitive target = (NativeType.Primitive) operation.type();
        final boolean signed = signedConversion(function, operation, source);
        final String opcode;
        if (source.isInteger() && target.isInteger()) {
            opcode = source.bits() > target.bits() ? "trunc" : (signed ? "sext" : "zext");
        } else if (source.isInteger()) {
            opcode = signed ? "sitofp" : "uitofp";
        } else if (target.isInteger()) {
            opcode = signed ? "fptosi" : "fptoui";
        } else {
            opcode = source.bits() > target.bits() ? "fptrunc" : "fpext";
        }
        output.append(opcode).append(' ').append(type(source)).append(' ')
                .append(operand(function, operation.operands().get(0), aliases))
                .append(" to ").append(type(target));
    }

    private boolean signedConversion(
            final NativeFunction function,
            final NativeInstruction.Operation operation,
            final NativeType.Primitive source
    ) {
        final String attribute = operation.attributes().get("signed");
        if (attribute == null) {
            return source != NativeType.Primitive.I1;
        }
        if (attribute.equalsIgnoreCase("true")) {
            return true;
        }
        if (attribute.equalsIgnoreCase("false")) {
            return false;
        }
        throw unsupported(function, "invalid CONVERT signed attribute: " + attribute);
    }

    private void validateAttributes(
            final NativeFunction function,
            final NativeInstruction.Operation operation
    ) {
        final Set<String> permitted = switch (operation.opcode()) {
            case CONVERT -> Set.of("signed");
            case REF_CAST -> Set.of();
            case STRING_CONSTANT -> Set.of("value");
            default -> Set.of();
        };
        final Set<String> unknown = new TreeSet<>(operation.attributes().keySet());
        unknown.removeAll(permitted);
        if (!unknown.isEmpty()) {
            throw unsupported(function, "attributes " + unknown + " on " + operation.opcode());
        }
        if (operation.opcode() == NativeOpcode.CONVERT && operation.attributes().containsKey("signed")) {
            final String signed = operation.attributes().get("signed");
            if (!signed.equalsIgnoreCase("true") && !signed.equalsIgnoreCase("false")) {
                throw unsupported(function, "invalid CONVERT signed attribute: " + signed);
            }
        }
    }

    private void emitTerminator(
            final NativeFunction function,
            final NativeBlock block,
            final NativeTerminator terminator,
            final Map<String, NativeOperand> aliases,
            final StringBuilder output,
            final SemanticSites semanticSites,
            final ControlFlowLayout layout,
            final int dispatchIndex
    ) {
        output.append("  ");
        if (terminator instanceof NativeTerminator.Return returning) {
            if (returning.value().isPresent()) {
                output.append("ret ").append(typedOperand(function, returning.value().orElseThrow(), aliases));
            } else {
                output.append("ret void");
            }
        } else if (terminator instanceof NativeTerminator.Branch branch) {
            output.append("br label %").append(blockName(branch.target()));
        } else if (terminator instanceof NativeTerminator.ConditionalBranch branch) {
            output.append("br i1 ").append(operand(function, branch.condition(), aliases))
                    .append(", label %").append(blockName(branch.trueTarget()))
                    .append(", label %").append(blockName(branch.falseTarget()));
        } else if (terminator instanceof NativeTerminator.Switch switching) {
            output.append("switch ").append(typedOperand(function, switching.selector(), aliases))
                    .append(", label %").append(blockName(switching.defaultTarget())).append(" [\n");
            switching.cases().entrySet().stream()
                    .sorted(Map.Entry.comparingByKey())
                    .forEach(entry -> output.append("    ").append(type(switching.selector().type())).append(' ')
                            .append(switchConstant(function, (NativeType.Primitive) switching.selector().type(),
                                    BigInteger.valueOf(entry.getKey())))
                            .append(", label %").append(blockName(entry.getValue())).append('\n'));
            output.append("  ]");
        } else if (terminator instanceof NativeTerminator.Throw throwing) {
            if (!function.requiresSemanticContext()) {
                throw unsupported(function, "Java exception throw without a semantic context");
            }
            output.append("call void @\"")
                    .append(escapedBytes(semanticSites.throwSymbol(function, block)))
                    .append("\"(ptr ").append(semanticContextName()).append(", ")
                    .append(typedOperand(function, throwing.throwable(), aliases))
                    .append(")\n");
            emitExceptionDispatch(function, block, output, semanticSites, layout, dispatchIndex, false);
            return;
        } else {
            throw unsupported(function, "unknown terminator " + terminator.getClass().getName());
        }
        output.append('\n');
    }

    private String zeroValue(final NativeType nativeType) {
        if (nativeType instanceof NativeType.Reference || nativeType instanceof NativeType.Array) return "null";
        return switch ((NativeType.Primitive) nativeType) {
            case VOID -> throw new IllegalArgumentException("void has no value");
            case I1 -> "false";
            case I8, I16, I32, I64 -> "0";
            case F32, F64 -> "0.000000e+00";
        };
    }

    private String typedOperand(
            final NativeFunction function,
            final NativeOperand operand,
            final Map<String, NativeOperand> aliases
    ) {
        return type(operand.type()) + " " + operand(function, operand, aliases);
    }

    private String operand(
            final NativeFunction function,
            final NativeOperand original,
            final Map<String, NativeOperand> aliases
    ) {
        final NativeOperand operand = resolveAlias(original, aliases);
        if (operand instanceof NativeOperand.Value value) {
            return valueName(value.id());
        }
        final NativeOperand.Constant constant = (NativeOperand.Constant) operand;
        if (constant.type() instanceof NativeType.Reference || constant.type() instanceof NativeType.Array) {
            if (constant.value() != null) {
                throw unsupported(function, "non-null Java reference constant");
            }
            return "null";
        }
        final NativeType.Primitive primitive = (NativeType.Primitive) constant.type();
        if (primitive == NativeType.Primitive.I1) {
            return Boolean.TRUE.equals(constant.value()) ? "true" : "false";
        }
        if (primitive.isInteger()) {
            return integerConstant(function, primitive, exactInteger(function, constant.value()));
        }
        return floatingConstant(function, primitive, constant.value());
    }

    private NativeOperand resolveAlias(final NativeOperand operand, final Map<String, NativeOperand> aliases) {
        NativeOperand resolved = operand;
        final Set<String> seen = new HashSet<>();
        while (resolved instanceof NativeOperand.Value value && aliases.containsKey(value.id())) {
            if (!seen.add(value.id())) {
                throw new LlvmEmissionException("Cyclic SSA aliases involving " + value.id());
            }
            resolved = aliases.get(value.id());
        }
        return resolved;
    }

    private BigInteger exactInteger(final NativeFunction function, final Object value) {
        try {
            if (value instanceof BigInteger integer) {
                return integer;
            }
            if (value instanceof BigDecimal decimal) {
                return decimal.toBigIntegerExact();
            }
            if (value instanceof Byte || value instanceof Short || value instanceof Integer || value instanceof Long) {
                return BigInteger.valueOf(((Number) value).longValue());
            }
            return new BigDecimal(value.toString()).toBigIntegerExact();
        } catch (final ArithmeticException | NumberFormatException exception) {
            throw new LlvmEmissionException("Function " + function.symbol()
                    + " contains a non-integral integer constant: " + value, exception);
        }
    }

    private String integerConstant(
            final NativeFunction function,
            final NativeType.Primitive type,
            final BigInteger value
    ) {
        if (!type.isInteger()) {
            throw new AssertionError(type);
        }
        final BigInteger minimum = BigInteger.ONE.shiftLeft(type.bits() - 1).negate();
        final BigInteger maximum = BigInteger.ONE.shiftLeft(type.bits()).subtract(BigInteger.ONE);
        if (value.compareTo(minimum) < 0 || value.compareTo(maximum) > 0) {
            throw unsupported(function, "integer constant " + value + " outside " + type.displayName());
        }
        return value.toString();
    }

    private String switchConstant(
            final NativeFunction function,
            final NativeType.Primitive type,
            final BigInteger value
    ) {
        if (type == NativeType.Primitive.I1) {
            if (value.equals(BigInteger.ZERO)) {
                return "false";
            }
            if (value.equals(BigInteger.ONE)) {
                return "true";
            }
            throw unsupported(function, "i1 switch case outside 0..1: " + value);
        }
        final BigInteger minimum = BigInteger.ONE.shiftLeft(type.bits() - 1).negate();
        final BigInteger maximum = BigInteger.ONE.shiftLeft(type.bits() - 1).subtract(BigInteger.ONE);
        if (value.compareTo(minimum) < 0 || value.compareTo(maximum) > 0) {
            throw unsupported(function, "switch case " + value + " outside signed " + type.displayName());
        }
        return value.toString();
    }

    private String floatingConstant(
            final NativeFunction function,
            final NativeType.Primitive type,
            final Object value
    ) {
        if (!(value instanceof Number number)) {
            throw unsupported(function, "non-numeric floating-point constant " + value);
        }
        final long bits;
        if (type == NativeType.Primitive.F32) {
            bits = Double.doubleToRawLongBits((double) number.floatValue());
        } else if (type == NativeType.Primitive.F64) {
            bits = Double.doubleToRawLongBits(number.doubleValue());
        } else {
            throw new AssertionError(type);
        }
        return String.format(java.util.Locale.ROOT, "0x%016X", bits);
    }

    private String type(final NativeType type) {
        if (type instanceof NativeType.Reference || type instanceof NativeType.Array) {
            return "ptr";
        }
        return switch ((NativeType.Primitive) type) {
            case VOID -> "void";
            case I1 -> "i1";
            case I8 -> "i8";
            case I16 -> "i16";
            case I32 -> "i32";
            case I64 -> "i64";
            case F32 -> "float";
            case F64 -> "double";
        };
    }

    private LlvmEmissionException unsupported(final NativeFunction function, final String feature) {
        return new LlvmEmissionException("Function " + function.symbol()
                + " cannot be emitted as canonical LLVM IR: unsupported " + feature);
    }

    private String valueName(final String id) {
        return "%\"" + escapedBytes("v." + id) + "\"";
    }

    private String semanticContextName() {
        return "%\"skid.semantic.context\"";
    }

    /** Returns the exact global symbol that the registration/trampoline layer must call. */
    public String emittedFunctionSymbol(final NativeFunction function) {
        return Objects.requireNonNull(function, "function").symbol();
    }

    private String blockName(final String id) {
        return "\"" + escapedBytes("b." + id) + "\"";
    }

    private static String escapedBytes(final String value) {
        final byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        final StringBuilder escaped = new StringBuilder(bytes.length);
        for (final byte item : bytes) {
            final int unsigned = item & 0xff;
            if (unsigned >= 0x20 && unsigned <= 0x7e && unsigned != '"' && unsigned != '\\') {
                escaped.append((char) unsigned);
            } else {
                escaped.append('\\');
                final String hex = Integer.toHexString(unsigned).toUpperCase(java.util.Locale.ROOT);
                if (hex.length() == 1) {
                    escaped.append('0');
                }
                escaped.append(hex);
            }
        }
        return escaped.toString();
    }

    /** Maps native block predecessors onto the split LLVM blocks introduced by exception checks. */
    private final class ControlFlowLayout {
        private final Map<String, NativeBlock> blocks;
        private final Map<String, Integer> operationDispatchCounts;
        private final Map<String, Integer> totalDispatchCounts;
        private final Map<String, Map<String, Integer>> exceptionAvailability;

        private ControlFlowLayout(final NativeFunction function, final List<NativeBlock> orderedBlocks) {
            final Map<String, NativeBlock> byId = new HashMap<>();
            final Map<String, Integer> operationCounts = new HashMap<>();
            final Map<String, Integer> totalCounts = new HashMap<>();
            final Map<String, Map<String, Integer>> availability = new HashMap<>();
            for (final NativeBlock block : orderedBlocks) {
                byId.put(block.id(), block);
                int count = 0;
                final Map<String, Integer> definitions = new HashMap<>();
                for (final NativeInstruction instruction : block.instructions()) {
                    if (instruction instanceof NativeInstruction.Operation operation) {
                        final boolean dispatch = requiresExceptionDispatch(operation);
                        // A result from a potentially-throwing operation does not exist on its own
                        // exceptional path. It becomes available only after that dispatch clears.
                        definitions.put(operation.id(), count + (dispatch ? 1 : 0));
                        if (dispatch) count++;
                    } else {
                        definitions.put(instruction.id(), count);
                    }
                }
                operationCounts.put(block.id(), count);
                totalCounts.put(block.id(), count
                        + (block.terminator().orElseThrow() instanceof NativeTerminator.Throw ? 1 : 0));
                availability.put(block.id(), Map.copyOf(definitions));
            }
            this.blocks = Map.copyOf(byId);
            this.operationDispatchCounts = Map.copyOf(operationCounts);
            this.totalDispatchCounts = Map.copyOf(totalCounts);
            this.exceptionAvailability = Map.copyOf(availability);
        }

        private boolean requiresExceptionDispatch(final NativeInstruction.Operation operation) {
            return SEMANTIC_OPCODES.contains(operation.opcode())
                    || operation.opcode() == NativeOpcode.STRING_CONSTANT
                    || operation.opcode() == NativeOpcode.SDIV
                    || operation.opcode() == NativeOpcode.UDIV
                    || operation.opcode() == NativeOpcode.SREM
                    || operation.opcode() == NativeOpcode.UREM;
        }

        private boolean hasExceptionDispatch() {
            return totalDispatchCounts.values().stream().anyMatch(count -> count != 0);
        }

        private String exceptionEscapeLabel() {
            return blockName("skid.exception.escape");
        }

        private String continuationLabel(final NativeBlock block, final int oneBasedIndex) {
            return blockName(block.id() + ".skid.cont." + oneBasedIndex);
        }

        private String segmentLabel(final NativeBlock block, final int dispatchIndex) {
            return dispatchIndex == 0 ? blockName(block.id()) : continuationLabel(block, dispatchIndex);
        }

        private List<String> predecessors(
                final NativeFunction function,
                final NativeOperand incoming,
                final String sourceBlock,
                final String targetBlock
        ) {
            final NativeBlock source = blocks.get(sourceBlock);
            if (source == null) return List.of();
            final List<String> result = new ArrayList<>();
            final NativeTerminator terminator = source.terminator().orElseThrow();
            // A PHI has one value for every LLVM edge, not just each unique block.
            final long normalEdges = terminator instanceof NativeTerminator.Switch switching
                    ? java.util.stream.Stream.concat(switching.cases().values().stream(),
                            java.util.stream.Stream.of(switching.defaultTarget())).filter(targetBlock::equals).count()
                    : terminator.successors().stream().filter(targetBlock::equals).count();
            for (long edge = 0; edge < normalEdges; edge++)
                result.add(segmentLabel(source, operationDispatchCounts.get(sourceBlock)));
            if (source.exceptionEdges().stream().anyMatch(edge -> edge.handlerBlock().equals(targetBlock))) {
                final int availableFrom = incoming instanceof NativeOperand.Value value
                        ? exceptionAvailability.get(sourceBlock).getOrDefault(value.id(), 0)
                        : 0;
                if (availableFrom != 0 && totalDispatchCounts.get(sourceBlock) != 0) {
                    throw unsupported(function, "phi incoming value "
                            + ((NativeOperand.Value) incoming).id()
                            + " is not defined on every exception edge from block " + sourceBlock);
                }
                final long exceptionEdges = orderedExceptionEdges(source).stream()
                        .filter(edge -> edge.handlerBlock().equals(targetBlock)).count();
                for (int index = 0; index < totalDispatchCounts.get(sourceBlock); index++)
                    for (long edge = 0; edge < exceptionEdges; edge++) result.add(segmentLabel(source, index));
            }
            return List.copyOf(result);
        }
    }

    private static final class StringConstants {
        private final Map<String, String> namesByValue;
        private final Map<String, NativeStringProtection.ProtectedString> protectedByValue;

        private StringConstants(
                final List<NativeFunction> functions,
                final NativeStringProtection protection
        ) {
            final Set<String> values = new TreeSet<>();
            for (final NativeFunction function : functions) {
                for (final NativeBlock block : function.blocks()) {
                    for (final NativeInstruction instruction : block.instructions()) {
                        if (instruction instanceof NativeInstruction.Operation operation
                                && operation.opcode() == NativeOpcode.STRING_CONSTANT
                                && operation.attributes().containsKey("value")) {
                            values.add(operation.attributes().get("value"));
                        }
                    }
                }
            }
            final Map<String, String> names = new HashMap<>();
            final Map<String, NativeStringProtection.ProtectedString> protectedStrings = new HashMap<>();
            final Set<String> usedNames = new HashSet<>();
            int cacheId = 0;
            for (final String value : values) {
                final NativeStringProtection.ProtectedString protectedString = protection == null
                        ? null
                        : protection.protect(value, cacheId);
                final String base = protectedString == null
                        ? "skid.string." + utf16Digest(value)
                        : "skid.pstring." + protectedDigest(protectedString);
                String name = base;
                int suffix = 1;
                while (!usedNames.add(name)) {
                    name = base + "." + suffix++;
                }
                names.put(value, name);
                if (protectedString != null) {
                    protectedStrings.put(value, protectedString);
                }
                cacheId++;
            }
            this.namesByValue = Map.copyOf(names);
            this.protectedByValue = Map.copyOf(protectedStrings);
        }

        private String name(final String value) {
            final String name = namesByValue.get(value);
            if (name == null) {
                throw new LlvmEmissionException("Missing canonical UTF-16 string constant");
            }
            return name;
        }

        private String helperDeclaration() {
            if (protectedByValue.isEmpty()) {
                return "declare ptr @\"skid.semantic.string_constant.v1\"(ptr, ptr, i32)\n";
            }
            return "; Reversible per-build string encoding; fragmented material remains client-recoverable.\n"
                    + "declare ptr @\"skid.semantic.string_constant.protected.v1\""
                    + "(ptr, ptr, i32, i32, i64, i64)\n";
        }

        private void emitCall(
                final String value,
                final String semanticContext,
                final StringBuilder output
        ) {
            final NativeStringProtection.ProtectedString protectedString = protectedByValue.get(value);
            if (protectedString == null) {
                output.append("call ptr @\"skid.semantic.string_constant.v1\"(ptr ")
                        .append(semanticContext)
                        .append(", ptr @\"").append(name(value)).append("\", i32 ")
                        .append(value.length()).append(')');
                return;
            }
            output.append("call ptr @\"skid.semantic.string_constant.protected.v1\"(ptr ")
                    .append(semanticContext)
                    .append(", ptr @\"").append(name(value)).append("\", i32 ")
                    .append(value.length()).append(", i32 ").append(protectedString.cacheId())
                    .append(", i64 ").append(protectedString.fragmentA())
                    .append(", i64 ").append(protectedString.fragmentB()).append(')');
        }

        private void emitGlobals(final StringBuilder output) {
            namesByValue.entrySet().stream()
                    .sorted(Map.Entry.comparingByValue())
                    .forEach(entry -> {
                        final String value = entry.getKey();
                        final NativeStringProtection.ProtectedString protectedString = protectedByValue.get(value);
                        final int[] units = protectedString == null
                                ? value.chars().toArray()
                                : protectedString.ciphertext();
                        output.append("@\"").append(entry.getValue()).append("\" = private unnamed_addr constant [")
                                .append(units.length).append(" x i16] ");
                        if (units.length == 0) {
                            output.append("zeroinitializer");
                        } else {
                            output.append('[');
                            for (int index = 0; index < units.length; index++) {
                                if (index != 0) {
                                    output.append(", ");
                                }
                                output.append("i16 ").append(units[index]);
                            }
                            output.append(']');
                        }
                        output.append(", align 2\n");
                    });
        }

        private static String protectedDigest(
                final NativeStringProtection.ProtectedString protectedString
        ) {
            try {
                final MessageDigest digest = MessageDigest.getInstance("SHA-256");
                digest.update(longBytes(protectedString.fragmentA()));
                digest.update(longBytes(protectedString.fragmentB()));
                for (final int unit : protectedString.ciphertext()) {
                    digest.update((byte) (unit >>> 8));
                    digest.update((byte) unit);
                }
                return java.util.HexFormat.of().formatHex(digest.digest(), 0, 12);
            } catch (NoSuchAlgorithmException exception) {
                throw new IllegalStateException("SHA-256 is unavailable", exception);
            }
        }

        private static byte[] longBytes(final long value) {
            return new byte[] {
                    (byte) (value >>> 56), (byte) (value >>> 48),
                    (byte) (value >>> 40), (byte) (value >>> 32),
                    (byte) (value >>> 24), (byte) (value >>> 16),
                    (byte) (value >>> 8), (byte) value
            };
        }

        private static String utf16Digest(final String value) {
            try {
                final MessageDigest digest = MessageDigest.getInstance("SHA-256");
                for (int index = 0; index < value.length(); index++) {
                    final char codeUnit = value.charAt(index);
                    digest.update((byte) (codeUnit >>> 8));
                    digest.update((byte) codeUnit);
                }
                final StringBuilder hex = new StringBuilder(64);
                for (final byte item : digest.digest()) {
                    hex.append(String.format(java.util.Locale.ROOT, "%02x", item & 0xff));
                }
                return hex.toString();
            } catch (final NoSuchAlgorithmException exception) {
                throw new IllegalStateException("SHA-256 is unavailable", exception);
            }
        }
    }

    private static final class Metadata {
        private final List<List<String>> nativeEntries = new ArrayList<>();
        private final List<List<String>> sourceEntries = new ArrayList<>();
        private final List<List<String>> semanticEntries = new ArrayList<>();

        private Metadata(final NativeModule module, final List<NativeFunction> functions) {
            final List<String> moduleEntry = new ArrayList<>(List.of(
                    "module", "name", module.name(), "abi", Integer.toString(module.abiVersion())));
            appendMap(moduleEntry, module.metadata());
            nativeEntries.add(moduleEntry);
            for (final NativeFunction function : functions) {
                final List<String> functionEntry = new ArrayList<>(List.of(
                        "function", "symbol", function.symbol(), "java.owner", function.javaOwner(),
                        "java.name", function.javaName(), "java.descriptor", function.javaDescriptor(),
                        "backend", function.backend().name(),
                        "requires-semantic-context", Boolean.toString(function.requiresSemanticContext())));
                if (!function.metadata().containsKey("java.static")) {
                    final int descriptorParameters = JavaDescriptor.method(function.javaDescriptor())
                            .parameters().size();
                    functionEntry.add("metadata.java.static");
                    functionEntry.add(Boolean.toString(function.parameters().size() == descriptorParameters));
                }
                appendMap(functionEntry, function.metadata());
                nativeEntries.add(functionEntry);
            }
        }

        private static void appendMap(final List<String> target, final Map<String, String> source) {
            source.entrySet().stream()
                    .sorted(Map.Entry.comparingByKey())
                    .forEach(entry -> {
                        target.add("metadata." + entry.getKey());
                        target.add(entry.getValue());
                    });
        }

        private void addSource(
                final NativeFunction function,
                final NativeBlock block,
                final String instruction,
                final SourceLocation location
        ) {
            if (location.equals(SourceLocation.UNKNOWN)) {
                return;
            }
            sourceEntries.add(List.of(
                    "source", "function", function.symbol(), "block", block.id(), "instruction", instruction,
                    "file", location.source(), "line", Integer.toString(location.line()),
                    "bytecode-offset", Integer.toString(location.bytecodeOffset())));
        }

        private void addSemantic(final List<String> entry) {
            semanticEntries.add(List.copyOf(entry));
        }

        private void emit(final StringBuilder output) {
            output.append('\n');
            int nextId = 0;
            output.append("!skid.native = !{");
            for (int index = 0; index < nativeEntries.size(); index++) {
                if (index != 0) {
                    output.append(", ");
                }
                output.append('!').append(nextId + index);
            }
            output.append("}\n");
            if (!sourceEntries.isEmpty()) {
                output.append("!skid.sources = !{");
                for (int index = 0; index < sourceEntries.size(); index++) {
                    if (index != 0) {
                        output.append(", ");
                    }
                    output.append('!').append(nativeEntries.size() + index);
                }
                output.append("}\n");
            }
            if (!semanticEntries.isEmpty()) {
                output.append("!skid.semantic.sites = !{");
                for (int index = 0; index < semanticEntries.size(); index++) {
                    if (index != 0) output.append(", ");
                    output.append('!').append(nativeEntries.size() + sourceEntries.size() + index);
                }
                output.append("}\n");
            }
            for (final List<String> entry : nativeEntries) {
                emitNode(output, nextId++, entry);
            }
            for (final List<String> entry : sourceEntries) {
                emitNode(output, nextId++, entry);
            }
            for (final List<String> entry : semanticEntries) {
                emitNode(output, nextId++, entry);
            }
        }

        private void emitNode(final StringBuilder output, final int id, final List<String> values) {
            output.append('!').append(id).append(" = !{");
            for (int index = 0; index < values.size(); index++) {
                if (index != 0) {
                    output.append(", ");
                }
                output.append("!\"").append(escapedBytes(values.get(index))).append('"');
            }
            output.append("}\n");
        }
    }

    /**
     * Typed, site-specific adapter ABI consumed by SkidLLVM's semantic lowering pass. Keeping Java
     * member/linkage data in canonical metadata avoids pretending that heterogeneous JNI calls
     * share one unsafe C signature while still producing valid canonical LLVM IR.
     */
    private final class SemanticSites {
        private final List<Site> sites = new ArrayList<>();
        private final Map<String, Site> operations = new HashMap<>();
        private final Map<String, Site> divideGuards = new HashMap<>();
        private final Map<String, Site> exceptionDispatches = new HashMap<>();
        private final Map<String, Site> throwsByBlock = new HashMap<>();

        private SemanticSites(final List<NativeFunction> functions) {
            for (final NativeFunction function : functions) {
                function.blocks().stream().sorted(Comparator.comparing(NativeBlock::id)).forEach(block -> {
                    for (final NativeInstruction instruction : block.instructions()) {
                        if (!(instruction instanceof NativeInstruction.Operation operation)) continue;
                        if (isIntegerDivision(operation.opcode())) {
                            final String symbol = "skid.semantic.site.v1." + function.symbol()
                                    + "." + operation.id() + ".java-div-guard";
                            final Site site = new Site(symbol, NativeType.Primitive.VOID,
                                    operation.operands().stream().map(NativeOperand::type).toList(),
                                    List.of("semantic-site", "symbol", symbol,
                                            "function", function.symbol(), "block", block.id(),
                                            "instruction", operation.id(),
                                            "opcode", "JAVA_" + operation.opcode().name() + "_GUARD",
                                            "result", "void",
                                            "operand", operation.operands().get(0).type().displayName(),
                                            "operand", operation.operands().get(1).type().displayName()));
                            divideGuards.put(operationKey(function, operation), site);
                            sites.add(site);
                        }
                        if (!SEMANTIC_OPCODES.contains(operation.opcode())) continue;
                        final String symbol = "skid.semantic.site.v1." + function.symbol() + "." + operation.id();
                        final List<String> metadata = new ArrayList<>(List.of(
                                "semantic-site", "symbol", symbol,
                                "function", function.symbol(), "block", block.id(),
                                "instruction", operation.id(), "opcode", operation.opcode().name(),
                                "result", operation.type().displayName()));
                        operation.operands().forEach(operand -> {
                            metadata.add("operand");
                            metadata.add(operand.type().displayName());
                        });
                        Metadata.appendMap(metadata, operation.attributes());
                        final Site site = new Site(symbol, operation.type(),
                                operation.operands().stream().map(NativeOperand::type).toList(), metadata);
                        operations.put(operationKey(function, operation), site);
                        sites.add(site);
                    }
                    if (block.terminator().orElseThrow() instanceof NativeTerminator.Throw throwing) {
                        final String symbol = "skid.semantic.site.v1." + function.symbol()
                                + "." + block.id() + ".throw";
                        final Site site = new Site(symbol, NativeType.Primitive.VOID,
                                List.of(throwing.throwable().type()),
                                List.of("semantic-site", "symbol", symbol, "function", function.symbol(),
                                        "block", block.id(), "instruction", "<terminator>",
                                        "opcode", "THROW", "result", "void",
                                        "operand", throwing.throwable().type().displayName()));
                        throwsByBlock.put(blockKey(function, block), site);
                        sites.add(site);
                    }
                    if (block.instructions().stream().anyMatch(instruction ->
                            instruction instanceof NativeInstruction.Operation operation
                                    && mayRaiseJavaException(operation.opcode()))
                            || block.terminator().orElseThrow() instanceof NativeTerminator.Throw) {
                        final String symbol = "skid.semantic.site.v1." + function.symbol()
                                + "." + block.id() + ".exception-dispatch";
                        final List<String> dispatchMetadata = new ArrayList<>(List.of(
                                "semantic-site", "symbol", symbol, "function", function.symbol(),
                                "block", block.id(), "instruction", "<exception-dispatch>",
                                "opcode", "EXCEPTION_DISPATCH", "result", "i32",
                                "status.clear", "-1", "status.uncaught", "default"));
                        final List<NativeExceptionEdge> edges = orderedExceptionEdges(block);
                        for (int index = 0; index < edges.size(); index++) {
                            final NativeExceptionEdge edge = edges.get(index);
                            dispatchMetadata.add("case");
                            dispatchMetadata.add(Integer.toString(index));
                            dispatchMetadata.add("priority");
                            dispatchMetadata.add(Integer.toString(edge.priority()));
                            dispatchMetadata.add("catch");
                            dispatchMetadata.add(edge.catchType().orElse("*"));
                            dispatchMetadata.add("handler");
                            dispatchMetadata.add(edge.handlerBlock());
                        }
                        final Site site = new Site(symbol, NativeType.Primitive.I32,
                                List.of(), dispatchMetadata);
                        exceptionDispatches.put(blockKey(function, block), site);
                        sites.add(site);
                    }
                });
            }
            sites.sort(Comparator.comparing(Site::symbol));
        }

        private boolean isIntegerDivision(final NativeOpcode opcode) {
            return opcode == NativeOpcode.SDIV || opcode == NativeOpcode.UDIV
                    || opcode == NativeOpcode.SREM || opcode == NativeOpcode.UREM;
        }

        private boolean mayRaiseJavaException(final NativeOpcode opcode) {
            return SEMANTIC_OPCODES.contains(opcode)
                    || opcode == NativeOpcode.STRING_CONSTANT || isIntegerDivision(opcode);
        }

        private String operationSymbol(
                final NativeFunction function,
                final NativeInstruction.Operation operation
        ) {
            final Site site = operations.get(operationKey(function, operation));
            if (site == null) throw new IllegalStateException("Missing semantic operation site");
            return site.symbol();
        }

        private String throwSymbol(final NativeFunction function, final NativeBlock block) {
            final Site site = throwsByBlock.get(blockKey(function, block));
            if (site == null) throw new IllegalStateException("Missing semantic throw site");
            return site.symbol();
        }

        private String divideGuardSymbol(
                final NativeFunction function,
                final NativeInstruction.Operation operation
        ) {
            final Site site = divideGuards.get(operationKey(function, operation));
            if (site == null) throw new IllegalStateException("Missing Java division guard site");
            return site.symbol();
        }

        private String exceptionDispatchSymbol(final NativeFunction function, final NativeBlock block) {
            final Site site = exceptionDispatches.get(blockKey(function, block));
            if (site == null) throw new IllegalStateException("Missing exception dispatch site");
            return site.symbol();
        }

        private void emitDeclarations(final StringBuilder output) {
            for (final Site site : sites) {
                output.append("declare ").append(type(site.result())).append(" @\"")
                        .append(escapedBytes(site.symbol())).append("\"(ptr");
                for (final NativeType operand : site.operands()) {
                    output.append(", ").append(type(operand));
                }
                output.append(")\n");
            }
        }

        private void addMetadata(final Metadata metadata) {
            sites.forEach(site -> metadata.addSemantic(site.metadata()));
        }

        private String operationKey(
                final NativeFunction function,
                final NativeInstruction.Operation operation
        ) {
            return function.symbol() + '\0' + operation.id();
        }

        private String blockKey(final NativeFunction function, final NativeBlock block) {
            return function.symbol() + '\0' + block.id();
        }

        private record Site(
                String symbol,
                NativeType result,
                List<NativeType> operands,
                List<String> metadata
        ) {
            private Site {
                operands = List.copyOf(operands);
                metadata = List.copyOf(metadata);
            }
        }
    }
}
