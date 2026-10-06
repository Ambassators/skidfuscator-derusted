package dev.skidfuscator.obfuscator.compatibility;

import dev.skidfuscator.obfuscator.Skidfuscator;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.commons.SimpleRemapper;
import org.objectweb.asm.tree.*;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.function.Function;
import java.util.function.Supplier;

/**
 * Captures runtime linkage contracts BEFORE any descriptor-changing pass runs.
 * A contract pins a member's ABI or a particular metadata value, not its body.
 * This is deliberately separate from the obfuscator's class/method exemptions.
 *
 * Literal reflection analysis is conservative, not a proof of closed-world
 * reflection. Assembled names, enumeration-based discovery and external APIs
 * need explicit contracts; unresolved discovery sites are included in reports.
 */
public final class RuntimeContractRegistry {
    private static final int METHOD_ABI = Opcodes.ACC_PUBLIC | Opcodes.ACC_PROTECTED | Opcodes.ACC_PRIVATE
            | Opcodes.ACC_STATIC | Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE;
    private static final int FIELD_ABI = Opcodes.ACC_PUBLIC | Opcodes.ACC_PROTECTED | Opcodes.ACC_PRIVATE
            | Opcodes.ACC_STATIC | Opcodes.ACC_FINAL;

    public record Options(List<String> methods, List<String> annotationElements,
                          List<String> exportedPackages, Map<String, String> classNames) {
        public Options {
            methods = List.copyOf(methods);
            annotationElements = List.copyOf(annotationElements);
            exportedPackages = List.copyOf(exportedPackages);
            classNames = Map.copyOf(classNames);
        }
        public static Options defaults() { return new Options(List.of(), List.of(), List.of(), Map.of()); }
    }

    private record MethodContract(ClassNode owner, MethodNode method, String name, String desc,
                                  int access, Set<String> reasons) { }
    private record FieldContract(ClassNode owner, FieldNode field, String name, String desc,
                                 int access, Object value, Set<String> reasons) { }
    private record ValueContract(String label, Supplier<Object> current, Object expected) { }

    private final Map<String, ClassNode> classes;
    private final Set<String> bodyOwners;
    private final Function<String, ClassNode> resolver;
    private final Options options;
    private final Map<String, String> originalNames = new HashMap<>();
    private final Set<String> annotationElements = new HashSet<>();
    private final Map<MethodNode, MethodContract> methods = new IdentityHashMap<>();
    private final Map<FieldNode, FieldContract> fields = new IdentityHashMap<>();
    private final List<ValueContract> values = new ArrayList<>();
    private final Set<String> discoverySites = new TreeSet<>();

    /** Suitable for isolated tests as well as embedding in another pipeline. */
    public RuntimeContractRegistry(Map<String, ClassNode> classes, Set<String> bodyOwners,
                                   Function<String, ClassNode> resolver, Options options) {
        this.classes = new LinkedHashMap<>(classes);
        this.bodyOwners = Set.copyOf(bodyOwners);
        this.resolver = resolver;
        this.options = options;
        // A RenameClient/SimpleRemapper TSV also contains private-member rows.
        // Only actual class destinations participate in reverse owner lookup.
        options.classNames().forEach((before, after) -> {
            if (classes.containsKey(after)) originalNames.put(after, before);
        });
        configureElements();
        captureBuiltins();
        captureUnrewrittenCallers(List.of());
        captureLiteralReflection();
        configureMethods();
        captureValues();
    }

    public static RuntimeContractRegistry capture(Skidfuscator skid) {
        Map<String, ClassNode> classes = new LinkedHashMap<>();
        Set<String> owned = new HashSet<>();
        for (org.mapleir.asm.ClassNode node : skid.getClassSource().iterate()) {
            classes.put(node.getName(), node.node);
            boolean unsupported = node instanceof dev.skidfuscator.obfuscator.skidasm.SkidClassNode application
                    && application.isAnnoyingVersion();
            if (!unsupported && !skid.getExemptAnalysis().isExempt(node)) owned.add(node.getName());
        }
        Map<String, String> names = readClassNames(skid.getConfig().getString("compatibility.nameMappingFile", ""));
        RuntimeContractRegistry registry = new RuntimeContractRegistry(classes, owned, name -> {
            org.mapleir.asm.ClassNode found = skid.getClassSource().findClassNode(name);
            return found == null ? null : found.node;
        }, new Options(
                skid.getConfig().getStringList("compatibility.methods", List.of()),
                skid.getConfig().getStringList("compatibility.annotationElements", List.of()),
                skid.getConfig().getStringList("compatibility.exportedPackages", List.of()), names));
        List<MethodNode> retainedCallers = new ArrayList<>();
        for (org.mapleir.asm.ClassNode node : skid.getClassSource().iterate()) {
            if (!owned.contains(node.getName())) continue;
            for (org.mapleir.asm.MethodNode method : node.getMethods())
                if (skid.getExemptAnalysis().isExempt(method)) retainedCallers.add(method.node);
        }
        if (!retainedCallers.isEmpty()) registry.captureUnrewrittenCallers(retainedCallers);
        for (String resource : skid.getConfig().getStringList("compatibility.bridgeDescriptors", List.of())) {
            boolean found = false;
            for (org.topdank.byteengineer.commons.data.JarResource entry : skid.getJarContents().getResourceContents()) {
                if (!resource.equals(entry.getName())) continue;
                String bridge = new String(entry.getData(), StandardCharsets.UTF_8).trim().split("\\R", 2)[0].replace('.', '/');
                if (!classes.containsKey(bridge)) throw new IllegalStateException("Missing bridge class declared by " + resource + ": " + bridge);
                registry.pinBridge(bridge);
                found = true;
            }
            if (!found) throw new IllegalStateException("Missing configured bridge descriptor: " + resource);
        }
        String report = skid.getConfig().getString("compatibility.reportPath", "");
        if (!report.isEmpty()) registry.writeReport(Path.of(report));
        Skidfuscator.LOGGER.warn("Runtime contracts: " + registry.methods.size() + " member ABIs, "
                + registry.fields.size() + " fields, " + registry.values.size()
                + " metadata values; bodies remain eligible. " + registry.discoverySites.size()
                + " reflection discovery sites require review (not proof of complete reflection coverage).");
        return registry;
    }

    private static Map<String, String> readClassNames(String file) {
        if (file.isEmpty()) return Map.of();
        try {
            Map<String, String> result = new HashMap<>();
            for (String line : Files.readAllLines(Path.of(file), StandardCharsets.UTF_8)) {
                if (line.isBlank() || line.startsWith("#")) continue;
                String[] cells = line.split("\t", -1);
                if (cells.length != 2 || cells[0].isEmpty() || cells[1].isEmpty())
                    throw new IllegalArgumentException("Expected a two-column symbol mapping: " + line);
                String previous = result.putIfAbsent(cells[0], cells[1]);
                if (previous != null && !previous.equals(cells[1])) throw new IllegalArgumentException("Conflicting class mapping: " + cells[0]);
            }
            return result;
        } catch (IOException error) { throw new IllegalStateException("Cannot read compatibility class mapping " + file, error); }
    }

    private String original(String name) { return originalNames.getOrDefault(name, name); }
    private boolean exported(ClassNode owner) {
        String name = original(owner.name);
        return options.exportedPackages().stream().map(p -> p.replace('.', '/'))
                .map(p -> p.endsWith("/") ? p : p + "/").anyMatch(name::startsWith);
    }
    private boolean inherits(ClassNode owner, String prefix) {
        Set<String> seen = new HashSet<>();
        Deque<String> pending = new ArrayDeque<>();
        pending.add(owner.name);
        while (!pending.isEmpty()) {
            String name = pending.remove();
            if (!seen.add(name)) continue;
            if (name.equals(prefix) || name.startsWith(prefix + "$")) return true;
            ClassNode type = classes.get(name);
            if (type == null) type = resolver.apply(name);
            if (type == null) continue;
            if (type.superName != null) pending.add(type.superName);
            pending.addAll(type.interfaces);
        }
        return false;
    }
    private static boolean visible(int flags) { return (flags & (Opcodes.ACC_PUBLIC | Opcodes.ACC_PROTECTED)) != 0; }
    private static boolean annotated(List<? extends AnnotationNode> annotations) { return annotations != null && !annotations.isEmpty(); }
    private static boolean structural(String desc) {
        return desc.startsWith("Lorg/spongepowered/asm/mixin/") || desc.startsWith("Lnet/minecraftforge/")
                || desc.startsWith("Lcpw/mods/fml/") || desc.startsWith("Ljava/lang/annotation/");
    }
    private static boolean callback(MethodNode method) {
        if (annotated(method.visibleAnnotations)) return true;
        return method.invisibleAnnotations != null && method.invisibleAnnotations.stream().anyMatch(a -> structural(a.desc));
    }

    private void captureBuiltins() {
        for (ClassNode owner : classes.values()) {
            if (!bodyOwners.contains(owner.name)) continue;
            boolean jnaLibrary = inherits(owner, "com/sun/jna/Library");
            boolean jnaStructure = inherits(owner, "com/sun/jna/Structure");
            boolean protobuf = inherits(owner, "com/google/protobuf/GeneratedMessageLite")
                    || inherits(owner, "com/google/protobuf/GeneratedMessageV3")
                    || inherits(owner, "com/google/protobuf/GeneratedMessage");
            boolean api = exported(owner);
            for (MethodNode method : owner.methods) {
                if (callback(method)) pin(owner, method, "runtime annotation/callback");
                if ((owner.access & Opcodes.ACC_ANNOTATION) != 0) pin(owner, method, "annotation element ABI");
                if ((owner.access & Opcodes.ACC_ENUM) != 0 &&
                        ((method.name.equals("values") && method.desc.equals("()[L" + owner.name + ";"))
                        || (method.name.equals("valueOf") && method.desc.equals("(Ljava/lang/String;)L" + owner.name + ";"))))
                    pin(owner, method, "enum reflection ABI");
                if ((method.access & Opcodes.ACC_NATIVE) != 0) pin(owner, method, "native ABI");
                if (jnaLibrary && (method.access & Opcodes.ACC_ABSTRACT) != 0) pin(owner, method, "JNA export ABI");
                if (jnaStructure && (visible(method.access) || method.name.equals("getFieldOrder"))) pin(owner, method, "JNA structure ABI");
                if (protobuf && visible(method.access)) pin(owner, method, "protobuf runtime/public factory ABI");
                // MessageLiteToString enumerates declared instance setters of every visibility
                // to decide which public getters represent printable fields.
                if (protobuf && (method.access & Opcodes.ACC_STATIC) == 0 && method.name.startsWith("set"))
                    pin(owner, method, "protobuf reflective setter discovery");
                if (api && visible(method.access)) pin(owner, method, "configured exported API");
                if (serializationHook(method)) pin(owner, method, "Java serialization hook");
            }
            for (FieldNode field : owner.fields) {
                if (visible(field.access) || annotated(field.visibleAnnotations)
                        || (jnaStructure && (field.access & Opcodes.ACC_STATIC) == 0)
                        || field.name.equals("serialVersionUID")) pin(owner, field, "public/annotated/native/serialization field");
            }
        }
        // A field read encoded in bytecode is not necessarily javac-inlined.
        for (ClassNode caller : classes.values()) for (MethodNode method : caller.methods)
            for (AbstractInsnNode instruction : method.instructions) if (instruction instanceof FieldInsnNode reference) {
                ClassNode owner = classes.get(reference.owner);
                if (owner == null || !bodyOwners.contains(owner.name)) continue;
                for (FieldNode field : owner.fields)
                    if (field.name.equals(reference.name) && field.desc.equals(reference.desc)) pin(owner, field, "symbolic field reference");
            }
    }

    private static boolean serializationHook(MethodNode method) {
        return (method.name.equals("readObject") && method.desc.equals("(Ljava/io/ObjectInputStream;)V"))
                || (method.name.equals("writeObject") && method.desc.equals("(Ljava/io/ObjectOutputStream;)V"))
                || (method.name.equals("readObjectNoData") && method.desc.equals("()V"))
                || ((method.name.equals("readResolve") || method.name.equals("writeReplace")) && method.desc.equals("()Ljava/lang/Object;"));
    }

    private void pinBridge(String bridge) {
        for (ClassNode owner : classes.values()) if (owner.name.equals(bridge) || owner.name.startsWith(bridge + "$")) {
            for (MethodNode method : owner.methods) if (visible(method.access)) pin(owner, method, "descriptor-declared native bridge ABI");
            for (FieldNode field : owner.fields) if (visible(field.access)) pin(owner, field, "descriptor-declared native bridge field");
        }
    }

    private record BoundarySymbol(String owner, String name, String desc, boolean method) { }

    /**
     * An untouched caller cannot acquire a new seed argument or return adapter.
     * Preserve only the referenced ABI, including inherited declarations and
     * constant-pool handles; the target's implementation is still transformable.
     * Call before any descriptor-changing pass. Explicitly retained methods may
     * be supplied in addition to classes outside the owned transformation scope.
     */
    public void captureUnrewrittenCallers(Collection<MethodNode> retainedMethods) {
        Set<MethodNode> retained = Collections.newSetFromMap(new IdentityHashMap<>());
        retained.addAll(retainedMethods);
        Map<BoundarySymbol, Optional<ClassNode>> declarations = new HashMap<>();
        for (ClassNode caller : classes.values()) for (MethodNode method : caller.methods) {
            if (bodyOwners.contains(caller.name) && !retained.contains(method)) continue;
            String reason = "unrewritten caller ABI: " + caller.name + "#" + method.name + method.desc;
            for (AbstractInsnNode instruction : method.instructions) {
                if (instruction instanceof MethodInsnNode call) {
                    pinBoundary(new BoundarySymbol(call.owner, call.name, call.desc, true), reason, declarations);
                } else if (instruction instanceof FieldInsnNode field) {
                    pinBoundary(new BoundarySymbol(field.owner, field.name, field.desc, false), reason, declarations);
                } else if (instruction instanceof LdcInsnNode ldc) {
                    pinBoundaryConstant(ldc.cst, reason, declarations);
                } else if (instruction instanceof InvokeDynamicInsnNode indy) {
                    pinBoundaryConstant(indy.bsm, reason, declarations);
                    for (Object argument : indy.bsmArgs) pinBoundaryConstant(argument, reason, declarations);
                }
            }
        }
    }

    private void pinBoundaryConstant(Object value, String reason,
                                     Map<BoundarySymbol, Optional<ClassNode>> declarations) {
        if (value instanceof org.objectweb.asm.Handle handle) {
            boolean method = handle.getTag() >= Opcodes.H_INVOKEVIRTUAL;
            pinBoundary(new BoundarySymbol(handle.getOwner(), handle.getName(), handle.getDesc(), method), reason, declarations);
        } else if (value instanceof org.objectweb.asm.ConstantDynamic dynamic) {
            pinBoundaryConstant(dynamic.getBootstrapMethod(), reason, declarations);
            for (int i = 0; i < dynamic.getBootstrapMethodArgumentCount(); i++)
                pinBoundaryConstant(dynamic.getBootstrapMethodArgument(i), reason, declarations);
        }
    }

    private void pinBoundary(BoundarySymbol symbol, String reason,
                             Map<BoundarySymbol, Optional<ClassNode>> declarations) {
        ClassNode owner = declarations.computeIfAbsent(symbol,
                key -> Optional.ofNullable(declaration(key.owner, key, new HashSet<>()))).orElse(null);
        if (owner == null || !bodyOwners.contains(owner.name)) return;
        if (symbol.method) {
            for (MethodNode method : owner.methods)
                if (method.name.equals(symbol.name) && method.desc.equals(symbol.desc)) pin(owner, method, reason);
        } else {
            for (FieldNode field : owner.fields)
                if (field.name.equals(symbol.name) && field.desc.equals(symbol.desc)) pin(owner, field, reason);
        }
    }

    private ClassNode declaration(String name, BoundarySymbol symbol, Set<String> seen) {
        if (name == null || !seen.add(name)) return null;
        ClassNode owner = classes.get(name);
        if (owner == null) owner = resolver.apply(name);
        if (owner == null) return null;
        if (symbol.method) {
            for (MethodNode method : owner.methods)
                if (method.name.equals(symbol.name) && method.desc.equals(symbol.desc)) return owner;
            if (symbol.name.equals("<init>") || symbol.name.equals("<clinit>")) return null;
        } else {
            for (FieldNode field : owner.fields)
                if (field.name.equals(symbol.name) && field.desc.equals(symbol.desc)) return owner;
        }
        // JVM field resolution searches superinterfaces before the superclass;
        // class-method resolution searches the superclass first.
        ClassNode parent;
        if (symbol.method) {
            parent = declaration(owner.superName, symbol, seen);
            if (parent != null) return parent;
        }
        for (String iface : owner.interfaces) {
            parent = declaration(iface, symbol, seen);
            if (parent != null) return parent;
        }
        return symbol.method ? null : declaration(owner.superName, symbol, seen);
    }

    private void captureLiteralReflection() {
        Set<String> methodNames = new HashSet<>(), fieldNames = new HashSet<>();
        for (ClassNode owner : classes.values()) {
            if (!bodyOwners.contains(owner.name)) continue;
            for (MethodNode method : owner.methods) {
                Set<String> literals = new HashSet<>();
                boolean readsMethods = false, readsFields = false;
                for (AbstractInsnNode instruction : method.instructions) {
                    if (instruction instanceof LdcInsnNode ldc && ldc.cst instanceof String value) literals.add(value);
                    if (!(instruction instanceof MethodInsnNode call) || !call.owner.equals("java/lang/Class")) continue;
                    if (Set.of("getMethod", "getDeclaredMethod", "getMethods", "getDeclaredMethods").contains(call.name)) readsMethods = true;
                    if (Set.of("getField", "getDeclaredField", "getFields", "getDeclaredFields").contains(call.name)) readsFields = true;
                    if (readsMethods || readsFields) discoverySites.add(owner.name + "#" + method.name + method.desc + " -> " + call.name);
                }
                if (readsMethods) methodNames.addAll(literals);
                if (readsFields) fieldNames.addAll(literals);
            }
        }
        for (ClassNode owner : classes.values()) {
            if (!bodyOwners.contains(owner.name)) continue;
            for (MethodNode method : owner.methods) if (methodNames.contains(method.name)) {
                pin(owner, method, "conservative literal reflection name");
                if ((owner.access & Opcodes.ACC_ANNOTATION) != 0) annotationElements.add(owner.name + "#" + method.name);
            }
            for (FieldNode field : owner.fields) if (fieldNames.contains(field.name)) pin(owner, field, "conservative literal reflection name");
        }
    }

    private void configureElements() {
        for (String specification : options.annotationElements()) {
            int separator = specification.indexOf('#');
            if (separator < 1 || separator == specification.length() - 1)
                throw new IllegalArgumentException("Annotation element contract must be owner#element: " + specification);
            String owner = specification.substring(0, separator).replace('.', '/');
            String mapped = options.classNames().getOrDefault(owner, owner);
            String name = specification.substring(separator + 1);
            ClassNode type = classes.get(mapped);
            if (type == null || (type.access & Opcodes.ACC_ANNOTATION) == 0
                    || type.methods.stream().noneMatch(m -> m.name.equals(name)))
                throw new IllegalArgumentException("Unresolved annotation element contract: " + specification);
            annotationElements.add(mapped + "#" + name);
        }
    }
    private void configureMethods() {
        SimpleRemapper remapper = new SimpleRemapper(options.classNames());
        for (String specification : options.methods()) {
            int separator = specification.indexOf('#'), descriptor = specification.indexOf('(', separator + 1);
            if (separator < 1 || descriptor <= separator + 1)
                throw new IllegalArgumentException("Method contract must be owner#name(descriptor): " + specification);
            String originalOwner = specification.substring(0, separator).replace('.', '/');
            String originalName = specification.substring(separator + 1, descriptor);
            String originalDesc = specification.substring(descriptor);
            String ownerName = remapper.mapType(originalOwner);
            String name = remapper.mapMethodName(originalOwner, originalName, originalDesc);
            String desc = remapper.mapMethodDesc(originalDesc);
            ClassNode owner = classes.get(ownerName);
            MethodNode method = owner == null ? null : owner.methods.stream()
                    .filter(m -> m.name.equals(name) && m.desc.equals(desc)).findFirst().orElse(null);
            if (method == null) throw new IllegalArgumentException("Unresolved exact method contract (check renaming map): " + specification);
            pin(owner, method, "configured exact method");
        }
    }

    /**
     * Records only the implementation-kind transition performed by a successful
     * native commit. The Java owner/name/descriptor and caller-visible flags must
     * still be identical; arbitrary pass changes to ACC_NATIVE remain forbidden.
     */
    public void recordCommittedNativeImplementation(MethodNode method) {
        Objects.requireNonNull(method, "method");
        final MethodContract contract = methods.get(method);
        if (contract == null) return;
        if (!contract.owner.methods.contains(method)
                || !contract.name.equals(method.name) || !contract.desc.equals(method.desc)
                || (contract.access & (Opcodes.ACC_NATIVE | Opcodes.ACC_ABSTRACT)) != 0
                || (method.access & Opcodes.ACC_NATIVE) == 0
                || (method.access & METHOD_ABI) != (contract.access | Opcodes.ACC_NATIVE)
                || method.instructions.size() != 0) {
            throw new IllegalStateException("Native commit changed a caller-facing ABI: "
                    + contract.owner.name + "#" + contract.name + contract.desc);
        }
        methods.put(method, new MethodContract(contract.owner, method, contract.name,
                contract.desc, contract.access | Opcodes.ACC_NATIVE, contract.reasons));
    }

    public boolean isMethodContract(MethodNode method) { return methods.containsKey(method); }
    public boolean isFieldContract(FieldNode field) { return fields.containsKey(field); }

    /** A proven native-storage transition may replace ordinary symbolic/public field pins. */
    public boolean isNativeStorageFieldContract(FieldNode field) {
        FieldContract c = fields.get(field);
        return c != null && c.reasons.stream().anyMatch(reason ->
                !reason.equals("symbolic field reference")
                        && !reason.equals("public/annotated/native/serialization field"));
    }

    public void recordCommittedNativeFieldStorage(FieldNode field) {
        if (isNativeStorageFieldContract(field))
            throw new IllegalStateException("Native storage cannot remove a required field contract");
        // The field planner separately proves annotations, JNA, serialization, API,
        // surviving bytecode and final native accesses before this committed transition.
        fields.remove(field);
    }
    public boolean isAnnotationElementContract(String descriptor, String element) {
        if (descriptor == null || !descriptor.startsWith("L") || !descriptor.endsWith(";")) return false;
        String owner = descriptor.substring(1, descriptor.length() - 1);
        ClassNode type = classes.get(owner);
        return structural(descriptor) || !bodyOwners.contains(owner)
                || (type != null && exported(type)) || annotationElements.contains(owner + "#" + element);
    }
    private void pin(ClassNode owner, MethodNode method, String reason) {
        MethodContract contract = methods.computeIfAbsent(method,
                m -> new MethodContract(owner, m, m.name, m.desc, m.access & METHOD_ABI, new TreeSet<>()));
        contract.reasons.add(reason);
    }
    private void pin(ClassNode owner, FieldNode field, String reason) {
        FieldContract contract = fields.computeIfAbsent(field,
                f -> new FieldContract(owner, f, f.name, f.desc, f.access & FIELD_ABI, f.value, new TreeSet<>()));
        contract.reasons.add(reason);
    }

    private void captureValues() {
        for (ClassNode owner : classes.values()) {
            if (!bodyOwners.contains(owner.name)) continue;
            // Traverse metadata touched by the annotation passes and retain
            // original values through tree identities before those passes run.
            recordAnnotations(owner.visibleAnnotations); recordAnnotations(owner.invisibleAnnotations);
            recordAnnotations(owner.visibleTypeAnnotations); recordAnnotations(owner.invisibleTypeAnnotations);
            for (FieldNode field : owner.fields) {
                recordAnnotations(field.visibleAnnotations); recordAnnotations(field.invisibleAnnotations);
                recordAnnotations(field.visibleTypeAnnotations); recordAnnotations(field.invisibleTypeAnnotations);
            }
            for (MethodNode method : owner.methods) {
                recordAnnotations(method.visibleAnnotations); recordAnnotations(method.invisibleAnnotations);
                recordAnnotations(method.visibleTypeAnnotations); recordAnnotations(method.invisibleTypeAnnotations);
                recordAnnotations(method.visibleLocalVariableAnnotations); recordAnnotations(method.invisibleLocalVariableAnnotations);
                if (method.visibleParameterAnnotations != null) for (List<AnnotationNode> list : method.visibleParameterAnnotations) recordAnnotations(list);
                if (method.invisibleParameterAnnotations != null) for (List<AnnotationNode> list : method.invisibleParameterAnnotations) recordAnnotations(list);
                if (method.annotationDefault != null && isAnnotationElementContract("L" + owner.name + ";", method.name))
                    values.add(new ValueContract(owner.name + "#" + method.name + " default", () -> method.annotationDefault, frozen(method.annotationDefault)));
            }
        }
    }
    private void recordAnnotations(List<? extends AnnotationNode> annotations) {
        if (annotations == null) return;
        for (AnnotationNode annotation : annotations) {
            if (annotation.values == null) continue;
            for (int index = 0; index + 1 < annotation.values.size(); index += 2) {
                String name = (String) annotation.values.get(index);
                Object value = annotation.values.get(index + 1);
                if (isAnnotationElementContract(annotation.desc, name)) {
                    values.add(new ValueContract(annotation.desc + "#" + name, () -> annotationValue(annotation, name), frozen(value)));
                } else if (value instanceof AnnotationNode nested) recordAnnotations(List.of(nested));
                else if (value instanceof List<?> list) for (Object item : list)
                    if (item instanceof AnnotationNode nested) recordAnnotations(List.of(nested));
            }
        }
    }
    private static Object annotationValue(AnnotationNode annotation, String name) {
        if (annotation.values != null) for (int i = 0; i + 1 < annotation.values.size(); i += 2)
            if (name.equals(annotation.values.get(i))) return annotation.values.get(i + 1);
        return null;
    }
    private static Object frozen(Object value) {
        if (value instanceof AnnotationNode annotation) return List.of(annotation.desc, frozen(annotation.values == null ? List.of() : annotation.values));
        if (value instanceof List<?> list) return list.stream().map(RuntimeContractRegistry::frozen).toList();
        if (value instanceof String[] array) return List.of(array.clone());
        if (value != null && value.getClass().isArray()) {
            List<Object> values = new ArrayList<>();
            for (int i = 0; i < java.lang.reflect.Array.getLength(value); i++) values.add(frozen(java.lang.reflect.Array.get(value, i)));
            return List.copyOf(values);
        }
        return value;
    }

    /** Fail closed before serialization if a pass changed or removed a pinned ABI/value. */
    public void validate() {
        List<String> failures = new ArrayList<>();
        for (MethodContract c : methods.values()) if (!c.owner.methods.contains(c.method)
                || !c.name.equals(c.method.name) || !c.desc.equals(c.method.desc) || c.access != (c.method.access & METHOD_ABI))
            failures.add("method " + c.owner.name + "#" + c.name + c.desc + " " + c.reasons);
        for (FieldContract c : fields.values()) if (!c.owner.fields.contains(c.field)
                || !c.name.equals(c.field.name) || !c.desc.equals(c.field.desc) || c.access != (c.field.access & FIELD_ABI)
                || !Objects.equals(c.value, c.field.value)) failures.add("field " + c.owner.name + "#" + c.name + " " + c.reasons);
        for (ValueContract c : values) if (!Objects.equals(c.expected, frozen(c.current.get()))) failures.add("metadata " + c.label);
        if (!failures.isEmpty()) throw new IllegalStateException("Runtime contract violation(s), refusing output:\n" + String.join("\n", failures));
    }
    public void writeReport(Path path) {
        List<String> rows = new ArrayList<>();
        rows.add("# ABI/metadata constraints only; method bodies are NOT exempted.");
        rows.add("# Reflection discovery warnings are not a complete analysis of dynamic/external callers.");
        methods.values().stream().map(c -> "METHOD\t" + c.owner.name + "#" + c.name + c.desc + "\t" + String.join(", ", c.reasons)).sorted().forEach(rows::add);
        fields.values().stream().map(c -> "FIELD\t" + c.owner.name + "#" + c.name + ":" + c.desc + "\t" + String.join(", ", c.reasons)).sorted().forEach(rows::add);
        values.stream().map(c -> "METADATA\t" + c.label).distinct().sorted().forEach(rows::add);
        discoverySites.forEach(site -> rows.add("REVIEW_REFLECTION\t" + site));
        try {
            Path absolute = path.toAbsolutePath();
            if (absolute.getParent() != null) Files.createDirectories(absolute.getParent());
            Files.write(absolute, rows, StandardCharsets.UTF_8);
        } catch (IOException failure) { throw new IllegalStateException("Cannot write runtime contract report " + path, failure); }
    }
}
