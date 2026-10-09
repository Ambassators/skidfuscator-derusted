package dev.skidfuscator.obfuscator.mapping;

import com.google.gson.Gson;
import dev.skidfuscator.obfuscator.Skidfuscator;
import dev.skidfuscator.obfuscator.skidasm.SkidMethodNode;
import org.mapleir.ir.cfg.BasicBlock;
import org.mapleir.ir.code.CodeUnit;
import org.mapleir.ir.code.Expr;
import org.mapleir.ir.code.Stmt;
import org.objectweb.asm.tree.*;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

/** Private sidecar provenance. Never serializes emitted constants or notice literals. */
public final class DebugMappings {
    private final Path directory;
    private final Map<MethodNode, Map<String, Object>> methods = new IdentityHashMap<>();
    private final Map<MethodNode, List<String>> derived = new IdentityHashMap<>();
    private final Map<BasicBlock, Map<String, Object>> blocks = new IdentityHashMap<>();
    private final Map<Expr, Map<String, Object>> stringExpressions = new IdentityHashMap<>();
    private final Map<AbstractInsnNode, List<Map<String, Object>>> traces = new IdentityHashMap<>();
    private final List<Map<String, Object>> strings = new ArrayList<>();
    private final List<Map<String, Object>> flow = new ArrayList<>();
    private final Map<MethodNode, Map<String, Deque<Map<String, Object>>>> literals = new IdentityHashMap<>();

    private DebugMappings(Path directory) { this.directory = directory; }

    public static DebugMappings capture(Skidfuscator skid) {
        String path = skid.getConfig().getString("debugMappings.directory", "");
        DebugMappings result = new DebugMappings(path.isEmpty() ? null : Paths.get(path));
        if (result.directory == null) return result;
        for (org.mapleir.asm.ClassNode owner : skid.getClassSource().iterate()) {
            if (owner.isVirtual() || skid.getExemptAnalysis().isExempt(owner)) continue;
            for (org.mapleir.asm.MethodNode method : owner.getMethods()) {
                MethodNode raw = method.node;
                Map<String, Object> row = row("id", "m" + result.methods.size(), "owner", owner.getName(),
                        "name", raw.name, "descriptor", raw.desc, "sourceFile", owner.node.sourceFile);
                List<Map<String, Object>> instructions = new ArrayList<>();
                Map<String, Deque<Map<String, Object>>> inputStrings = new HashMap<>();
                int index = 0, line = -1;
                for (AbstractInsnNode insn : raw.instructions) {
                    if (insn instanceof LineNumberNode) line = ((LineNumberNode) insn).line;
                    if (insn.getOpcode() < 0) continue;
                    instructions.add(row("index", index, "opcode", insn.getOpcode(), "line", line));
                    if (insn instanceof LdcInsnNode && ((LdcInsnNode) insn).cst instanceof String) {
                        inputStrings.computeIfAbsent((String) ((LdcInsnNode) insn).cst, k -> new ArrayDeque<>())
                                .add(row("index", index, "line", line));
                    }
                    index++;
                }
                row.put("instructions", instructions);
                result.methods.put(raw, row);
                result.literals.put(raw, inputStrings);
            }
        }
        return result;
    }

    /** Capture block object identities before the EventBus changes the graph. */
    public void captureFlow(Skidfuscator skid) {
        if (directory == null) return;
        for (org.mapleir.asm.ClassNode owner : skid.getHierarchy().getClasses()) {
            if (owner.isVirtual() || owner.isAnnoyingVersion() || skid.getExemptAnalysis().isExempt(owner)) continue;
            for (org.mapleir.asm.MethodNode wrapped : owner.getMethods()) {
                if (!(wrapped instanceof SkidMethodNode) || wrapped.isAbstract() || wrapped.isNative()
                        || skid.getExemptAnalysis().isExempt(wrapped)) continue;
                SkidMethodNode method = (SkidMethodNode) wrapped;
                for (BasicBlock block : method.getCfg().vertices()) {
                    Map<String, Object> trace = block(method, block);
                    trace.put("origin", "input-cfg-block");
                    List<Integer> successors = new ArrayList<>();
                    method.getCfg().getEdges(block).forEach(e -> successors.add(e.dst().getNumericId()));
                    Collections.sort(successors);
                    trace.put("inputSuccessors", successors);
                }
            }
        }
    }

    private Map<String, Object> block(SkidMethodNode method, BasicBlock block) {
        return blocks.computeIfAbsent(block, b -> {
            Map<String, Object> trace = row("id", "b" + flow.size(), "inputMethods", origins(method.node),
                    "blockId", block.getNumericId(), "origin", "generated-cfg-block");
            flow.add(trace);
            return trace;
        });
    }

    public void string(SkidMethodNode method, BasicBlock block, String plaintext, Expr replacement, String algorithm) {
        if (directory == null) return;
        Map<String, Object> trace = row("id", "s" + strings.size(), "inputMethods", origins(method.node),
                "block", block(method, block).get("id"), "plaintext", plaintext, "algorithm", algorithm);
        Map<String, Deque<Map<String, Object>>> values = literals.get(method.node);
        Deque<Map<String, Object>> sites = values == null ? null : values.get(plaintext);
        trace.put("inputSite", sites == null || sites.isEmpty() ? null : sites.removeFirst());
        trace.put("origin", trace.get("inputSite") == null ? "generated-or-relocated-literal" : "input-ldc");
        strings.add(trace);
        stringExpressions.put(replacement, trace);
    }

    /** Record only instruction identity/coordinates, never operand values. */
    public void emitted(SkidMethodNode method, BasicBlock block, Stmt statement, AbstractInsnNode previous) {
        if (directory == null) return;
        List<Map<String, Object>> labels = new ArrayList<>();
        labels.add(block(method, block));
        collectStrings(statement, labels);
        AbstractInsnNode first = previous == null ? method.node.instructions.getFirst() : previous.getNext();
        for (AbstractInsnNode insn = first; insn != null; insn = insn.getNext()) {
            if (insn.getOpcode() >= 0) traces.computeIfAbsent(insn, k -> new ArrayList<>()).addAll(labels);
        }
    }

    private void collectStrings(CodeUnit unit, List<Map<String, Object>> labels) {
        Map<String, Object> found = stringExpressions.get(unit);
        if (found != null) labels.add(found);
        for (Expr child : unit.children) if (child != null) collectStrings(child, labels);
    }

    public void copied(AbstractInsnNode original, AbstractInsnNode copy) {
        if (directory == null) return;
        List<Map<String, Object>> labels = traces.get(original);
        if (labels != null) traces.put(copy, new ArrayList<>(labels));
    }

    public void derived(MethodNode source, MethodNode generated) {
        if (directory == null) return;
        List<String> ids = derived.computeIfAbsent(generated, k -> new ArrayList<>());
        for (String id : origins(source)) if (!ids.contains(id)) ids.add(id);
    }

    private List<String> origins(MethodNode method) {
        Map<String, Object> input = methods.get(method);
        return input == null ? derived.getOrDefault(method, Collections.emptyList())
                : Collections.singletonList((String) input.get("id"));
    }

    public void write(Skidfuscator skid) {
        if (directory == null) return;
        Map<String, List<Integer>> written = writtenOpcodes(skid);
        List<Map<String, Object>> output = new ArrayList<>();
        Map<String, Boolean> coordinateChecks = new HashMap<>();
        Map<Map<String, Object>, Map<String, List<Integer>>> locations = new IdentityHashMap<>();
        Set<MethodNode> survivors = Collections.newSetFromMap(new IdentityHashMap<>());
        for (org.mapleir.asm.ClassNode owner : skid.getClassSource().iterate()) {
            if (owner.isVirtual() || skid.getExemptAnalysis().isExempt(owner)) continue;
            for (MethodNode method : owner.node.methods) {
                survivors.add(method);
                String target = skid.getClassRemapper().mapType(owner.getName()) + "#"
                        + skid.getClassRemapper().mapMethodName(owner.getName(), method.name, method.desc)
                        + skid.getClassRemapper().mapMethodDesc(method.desc);
                Set<String> sources = new LinkedHashSet<>(origins(method));
                List<Integer> opcodes = new ArrayList<>();
                int index = 0;
                for (AbstractInsnNode insn : method.instructions) {
                    if (insn.getOpcode() < 0) continue;
                    opcodes.add(insn.getOpcode());
                    for (Map<String, Object> trace : traces.getOrDefault(insn, Collections.emptyList())) {
                        locations.computeIfAbsent(trace, k -> new TreeMap<>())
                                .computeIfAbsent(target, k -> new ArrayList<>()).add(index);
                        sources.addAll((List<String>) trace.get("inputMethods"));
                    }
                    index++;
                }
                coordinateChecks.put(target, opcodes.equals(written.get(target)));
                output.add(row("target", target, "inputMethods", new ArrayList<>(sources),
                        "generated", !methods.containsKey(method), "opcodeCount", index,
                        "writtenOpcodeCount", written.containsKey(target) ? written.get(target).size() : null,
                        "coordinatesMatchWrittenMethod", coordinateChecks.get(target)));
            }
        }
        for (Map.Entry<MethodNode, Map<String, Object>> entry : methods.entrySet()) {
            entry.getValue().put("survivesAsMethod", survivors.contains(entry.getKey()));
        }
        List<Map<String, Object>> all = new ArrayList<>(flow); all.addAll(strings);
        for (Map<String, Object> trace : all) {
            List<Map<String, Object>> segments = new ArrayList<>();
            for (Map.Entry<String, List<Integer>> location : locations.getOrDefault(trace, Collections.emptyMap()).entrySet()) {
                SortedSet<Integer> indexes = new TreeSet<>(location.getValue());
                int start = -1, last = -1;
                for (int index : indexes) {
                    if (last >= 0 && index != last + 1) {
                        segments.add(row("method", location.getKey(), "start", start, "endExclusive", last + 1));
                        start = -1;
                    }
                    if (start < 0) start = index;
                    last = index;
                }
                if (start >= 0) segments.add(row("method", location.getKey(), "start", start, "endExclusive", last + 1));
            }
            for (Map<String, Object> segment : segments)
                segment.put("coordinatesMatchWrittenMethod", coordinateChecks.get(segment.get("method")));
            trace.put("segments", segments);
            trace.put("status", segments.isEmpty() ? "not-retained-or-untracked-rewrite" : "tracked");
        }
        List<Map<String, Object>> input = new ArrayList<>(methods.values());
        input.sort(Comparator.comparing(r -> r.get("owner") + "#" + r.get("name") + r.get("descriptor")));
        output.sort(Comparator.comparing(r -> (String) r.get("target")));
        try {
            Files.createDirectories(directory);
            jsonl("methods-input.jsonl", input); jsonl("methods-output.jsonl", output);
            jsonl("strings.jsonl", strings); jsonl("control-flow.jsonl", flow);
            Map<String, Object> manifest = row("schemaVersion", 1, "complete", true,
                    "coordinate", "pre-write ASM opcode ordinal; labels/frames/debug nodes excluded",
                    "stringRangePrecision", "containing emitted statement, not individual expression",
                    "flowPrecision", "CFG block lineage, not instruction-by-instruction inverse transformation",
                    "methodsWithVerifiedWrittenCoordinates", coordinateChecks.values().stream().filter(Boolean::booleanValue).count(),
                    "noticeContentsRecorded", false, "inputMethods", input.size(), "outputMethods", output.size(),
                    "stringSites", strings.size(), "flowBlocks", flow.size());
            Files.writeString(directory.resolve("manifest.json"), new Gson().toJson(manifest) + "\n", StandardCharsets.UTF_8);
        } catch (IOException e) { throw new IllegalStateException("Cannot write private debug mappings", e); }
    }

    private Map<String, List<Integer>> writtenOpcodes(Skidfuscator skid) {
        Map<String, List<Integer>> result = new HashMap<>();
        try (java.util.zip.ZipFile jar = new java.util.zip.ZipFile(skid.getSession().getOutput())) {
            java.util.Enumeration<? extends java.util.zip.ZipEntry> entries = jar.entries();
            while (entries.hasMoreElements()) {
                java.util.zip.ZipEntry entry = entries.nextElement();
                if (!entry.getName().endsWith(".class")) continue;
                org.objectweb.asm.tree.ClassNode owner = new org.objectweb.asm.tree.ClassNode();
                try (java.io.InputStream stream = jar.getInputStream(entry)) {
                    new org.objectweb.asm.ClassReader(stream).accept(owner,
                            org.objectweb.asm.ClassReader.SKIP_DEBUG | org.objectweb.asm.ClassReader.SKIP_FRAMES);
                }
                for (MethodNode method : owner.methods) {
                    List<Integer> opcodes = new ArrayList<>();
                    for (AbstractInsnNode insn : method.instructions)
                        if (insn.getOpcode() >= 0) opcodes.add(insn.getOpcode());
                    result.put(owner.name + "#" + method.name + method.desc, opcodes);
                }
            }
        } catch (IOException e) { throw new IllegalStateException("Cannot validate written mapping coordinates", e); }
        return result;
    }

    private void jsonl(String file, List<Map<String, Object>> rows) throws IOException {
        Gson gson = new Gson();
        try (java.io.BufferedWriter writer = Files.newBufferedWriter(directory.resolve(file), StandardCharsets.UTF_8)) {
            for (Map<String, Object> row : rows) { writer.write(gson.toJson(row)); writer.newLine(); }
        }
    }

    private static Map<String, Object> row(Object... pairs) {
        Map<String, Object> result = new LinkedHashMap<>();
        for (int i = 0; i < pairs.length; i += 2) result.put((String) pairs[i], pairs[i + 1]);
        return result;
    }
}
