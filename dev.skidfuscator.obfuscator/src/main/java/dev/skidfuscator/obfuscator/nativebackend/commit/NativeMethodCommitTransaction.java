package dev.skidfuscator.obfuscator.nativebackend.commit;

import dev.skidfuscator.obfuscator.nativebackend.NativeEligibility;
import dev.skidfuscator.obfuscator.nativebackend.JavaLinkageHelper;
import dev.skidfuscator.obfuscator.nativebackend.runtime.NativeLoaderGenerator;
import org.mapleir.asm.ClassHelper;
import org.mapleir.asm.ClassNode;
import org.mapleir.asm.MethodNode;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.MethodInsnNode;
import org.topdank.byteengineer.commons.data.JarClassData;
import org.topdank.byteengineer.commons.data.JarContents;
import org.topdank.byteengineer.commons.data.JarResource;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.IdentityHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Atomically installs staged native resources, a generated loader, loader initialization,
 * and the final Java-to-native method mutations.
 *
 * <p>Compilation and native registration-table generation happen before this boundary. A
 * failure at any point restores the complete class/resource lists and all touched methods.
 * Wrapper bytecode is supplied by the semantic lowering backend because constructor prefix
 * splitting and interface companion ownership cannot be inferred safely at this layer.</p>
 */
public final class NativeMethodCommitTransaction {
    private static final String NATIVE_ANNOTATION =
            "Ldev/skidfuscator/annotations/NativeObfuscation;";

    public CommitResult commit(
            final JarContents contents,
            final NativeLoaderGenerator.GeneratedLoader loader,
            final Collection<Mutation> mutations,
            final ResourceStager resourceStager
    ) throws IOException {
        return commit(contents, loader, mutations, List.of(), resourceStager);
    }

    public CommitResult commit(
            final JarContents contents,
            final NativeLoaderGenerator.GeneratedLoader loader,
            final Collection<Mutation> mutations,
            final Collection<JavaLinkageHelper> linkageHelpers,
            final ResourceStager resourceStager
    ) throws IOException {
        return commit(contents,loader,mutations,linkageHelpers,List.of(),resourceStager);
    }

    public record FieldRemoval(ClassNode owner, org.objectweb.asm.tree.FieldNode field) { }

    public CommitResult commit(
            final JarContents contents,
            final NativeLoaderGenerator.GeneratedLoader loader,
            final Collection<Mutation> mutations,
            final Collection<JavaLinkageHelper> linkageHelpers,
            final Collection<FieldRemoval> fieldRemovals,
            final ResourceStager resourceStager
    ) throws IOException {
        Objects.requireNonNull(contents, "contents");
        Objects.requireNonNull(loader, "loader");
        Objects.requireNonNull(mutations, "mutations");
        Objects.requireNonNull(linkageHelpers, "linkageHelpers");
        Objects.requireNonNull(resourceStager, "resourceStager");
        final List<Mutation> ordered = List.copyOf(mutations);
        final List<JavaLinkageHelper> helpers = List.copyOf(linkageHelpers);
        final List<FieldRemoval> fields = List.copyOf(fieldRemovals);
        for (FieldRemoval removal : fields) {
            var field=removal.field();
            if (!removal.owner().node.fields.contains(field)
                    || contents.getClassContents().stream().noneMatch(c->c.getClassNode()==removal.owner())
                    || field.desc.length()!=1 || "ZBCSIJFD".indexOf(field.desc.charAt(0))<0
                    || (field.access&(Opcodes.ACC_FINAL|Opcodes.ACC_ENUM))!=0 || field.value!=null)
                throw new IllegalArgumentException("Invalid reviewed native primitive field removal");
        }
        if (ordered.isEmpty()) {
            throw new IllegalArgumentException("At least one native method mutation is required");
        }

        final ClassNode loaderNode = preflight(contents, loader, ordered, helpers);
        final List<JarClassData> classSnapshot = new ArrayList<>(contents.getClassContents());
        final List<JarResource> resourceSnapshot = new ArrayList<>(contents.getResourceContents());
        final Map<org.objectweb.asm.tree.MethodNode, MethodSnapshot> methods = snapshots(ordered);
        final Map<ClassNode, ClassSnapshot> owners = ownerSnapshots(ordered, helpers);
        for (FieldRemoval field : fields) owners.putIfAbsent(field.owner(),new ClassSnapshot(field.owner()));
        try {
            // Native bytes and authenticated manifests must be durable in the output model first.
            final List<String> stagedResources = List.copyOf(resourceStager.stage(contents));
            contents.getClassContents().add(new JarClassData(
                    loader.internalName() + ".class", loader.bytecode(), loaderNode));

            for (final JavaLinkageHelper helper : helpers) {
                helper.owner().addMethod(new MethodNode(cloneMethod(helper.method()), helper.owner()));
            }

            installInitialization(ordered, loader.internalName());

            // Method bodies are changed only after every fallible staging and initialization step.
            for (final Mutation mutation : ordered) {
                applyMutation(mutation, loader.internalName());
            }
            for (FieldRemoval field : fields) {
                field.owner().node.fields.remove(field.field());
                field.owner().getFields().removeIf(f->f.node==field.field());
            }
            return new CommitResult(loader.internalName(), stagedResources, ordered.size());
        } catch (final IOException | RuntimeException | Error failure) {
            restoreMethods(methods);
            restoreOwners(owners);
            contents.getClassContents().clear();
            contents.getClassContents().addAll(classSnapshot);
            contents.getResourceContents().clear();
            contents.getResourceContents().addAll(resourceSnapshot);
            throw failure;
        }
    }

    private static ClassNode preflight(
            final JarContents contents,
            final NativeLoaderGenerator.GeneratedLoader loader,
            final List<Mutation> mutations,
            final List<JavaLinkageHelper> linkageHelpers
    ) {
        validateLoaderCollision(contents, loader.internalName());
        // This loader is installed after SSA/bytecode dumping and may be exempt
        // from later transforms. Preserve its generated Java 8 stack-map frames;
        // ClassHelper's default parser strips them and causes VerifyError.
        final ClassNode loaderNode = ClassHelper.create(loader.bytecode(), 0);
        if (!loader.internalName().equals(loaderNode.getName())) {
            throw new IllegalArgumentException("Generated loader name does not match its bytecode");
        }
        final Set<MethodNode> uniqueMethods = java.util.Collections.newSetFromMap(new IdentityHashMap<>());
        final Set<String> helperKeys = new LinkedHashSet<>();
        for (final Mutation mutation : mutations) {
            if (!uniqueMethods.add(mutation.method())) {
                throw new IllegalArgumentException("Method appears more than once in native commit: "
                        + mutation.method());
            }
            validateAttached(contents, mutation.method());
            if (mutation instanceof Direct || mutation instanceof JavaCopy || mutation instanceof Remove) {
                final NativeEligibility.Result eligibility = NativeEligibility.check(mutation.method());
                if (eligibility.conversion() != NativeEligibility.Conversion.DIRECT) {
                    throw new IllegalArgumentException("Method is not eligible for direct native conversion: "
                            + eligibility.reason());
                }
                if (mutation instanceof Remove removal && (((mutation.method().node.access & Opcodes.ACC_PRIVATE) == 0
                        && !removal.reviewedClosedWorld())
                        || (mutation.method().node.access & Opcodes.ACC_SYNCHRONIZED) != 0)) {
                    throw new IllegalArgumentException("Removal requires a proven private or reviewed closed-world, unsynchronized AOT entry");
                }
            } else if (mutation instanceof Wrapper wrapper) {
                validateWrapper(contents, wrapper, helperKeys);
            }
        }
        validateLinkageHelpers(contents, linkageHelpers);
        preflightInitializers(mutations);
        return loaderNode;
    }

    private static void validateLinkageHelpers(
            final JarContents contents,
            final List<JavaLinkageHelper> helpers
    ) {
        final Set<String> keys = new LinkedHashSet<>();
        for (final JavaLinkageHelper helper : helpers) {
            if (contents.getClassContents().stream()
                    .noneMatch(data -> data.getClassNode() == helper.owner())) {
                throw new IllegalArgumentException("Java linkage helper owner is not in the destination jar: "
                        + helper.owner().getName());
            }
            final org.objectweb.asm.tree.MethodNode method = helper.method();
            final int required = Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC;
            if ((method.access & required) != required
                    || (method.access & (Opcodes.ACC_NATIVE | Opcodes.ACC_ABSTRACT)) != 0
                    || method.name.startsWith("<") || method.instructions == null
                    || method.instructions.size() == 0) {
                throw new IllegalArgumentException(
                        "Java linkage helper must be static, synthetic, concrete, and code-bearing");
            }
            final String key = helper.owner().getName() + "#" + method.name + method.desc;
            if (!keys.add(key) || helper.owner().node.methods.stream()
                    .anyMatch(existing -> existing.name.equals(method.name)
                            && existing.desc.equals(method.desc))) {
                throw new IllegalArgumentException("Java linkage helper collides with an existing method: " + key);
            }
        }
    }

    private static void validateAttached(final JarContents contents, final MethodNode method) {
        Objects.requireNonNull(method, "method");
        if (!method.owner.getMethods().contains(method) || !method.owner.node.methods.contains(method.node)) {
            throw new IllegalArgumentException("Method is not attached to its declared owner: " + method);
        }
        if (contents.getClassContents().stream().noneMatch(data -> data.getClassNode() == method.owner)) {
            throw new IllegalArgumentException("Method owner is not in the destination jar: " + method.owner.getName());
        }
    }

    private static void validateWrapper(
            final JarContents contents,
            final Wrapper wrapper,
            final Set<String> helperKeys
    ) {
        final NativeEligibility.Result eligibility = NativeEligibility.check(wrapper.method());
        if (!eligibility.isSupported()) {
            throw new IllegalArgumentException("Method is not eligible for a native wrapper: " + eligibility.reason());
        }
        final org.objectweb.asm.tree.MethodNode template = wrapper.wrapperTemplate();
        if (!template.name.equals(wrapper.method().getName())
                || !template.desc.equals(wrapper.method().getDesc())
                || template.instructions == null || template.instructions.size() == 0
                || (template.access & (Opcodes.ACC_NATIVE | Opcodes.ACC_ABSTRACT)) != 0) {
            throw new IllegalArgumentException("Wrapper template must provide Code for the original name and descriptor");
        }
        final ClassNode helperOwner = wrapper.helperOwner();
        if (contents.getClassContents().stream().noneMatch(data -> data.getClassNode() == helperOwner)) {
            throw new IllegalArgumentException("Native helper owner is not in the destination jar: "
                    + helperOwner.getName());
        }
        final org.objectweb.asm.tree.MethodNode helper = wrapper.nativeHelper();
        final int required = Opcodes.ACC_NATIVE | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC;
        if ((helper.access & required) != required
                || (helper.access & Opcodes.ACC_ABSTRACT) != 0
                || helper.name.startsWith("<")
                || (helper.instructions != null && helper.instructions.size() != 0)) {
            throw new IllegalArgumentException("Native wrapper helper must be static, synthetic, native, and code-free");
        }
        if ((helperOwner.node.access & Opcodes.ACC_INTERFACE) != 0) {
            throw new IllegalArgumentException("Native helpers for interface methods require a non-interface companion");
        }
        final String key = helperOwner.getName() + "#" + helper.name + helper.desc;
        if (!helperKeys.add(key) || helperOwner.node.methods.stream()
                .anyMatch(method -> method.name.equals(helper.name) && method.desc.equals(helper.desc))) {
            throw new IllegalArgumentException("Native helper collides with an existing method: " + key);
        }
    }

    private static void preflightInitializers(final List<Mutation> mutations) {
        final Set<ClassNode> owners = java.util.Collections.newSetFromMap(new IdentityHashMap<>());
        for (final Mutation mutation : mutations) {
            if (isSelectedClassInitializer(mutation)) {
                continue;
            }
            if (!owners.add(mutation.method().owner)) {
                continue;
            }
            final List<org.objectweb.asm.tree.MethodNode> initializers = mutation.method().owner.node.methods.stream()
                    .filter(method -> "<clinit>".equals(method.name) && "()V".equals(method.desc))
                    .toList();
            if (initializers.size() > 1) {
                throw new IllegalStateException("Owner contains duplicate class initializers: "
                        + mutation.method().owner.getName());
            }
            if (!initializers.isEmpty()) {
                final org.objectweb.asm.tree.MethodNode initializer = initializers.get(0);
                if ((initializer.access & (Opcodes.ACC_NATIVE | Opcodes.ACC_ABSTRACT)) != 0
                        || initializer.instructions == null) {
                    throw new IllegalStateException("Class initializer cannot host native loader initialization");
                }
            }
        }
    }

    private static void installInitialization(final List<Mutation> mutations, final String loaderName) {
        final Set<ClassNode> initialized = java.util.Collections.newSetFromMap(new IdentityHashMap<>());
        for (final Mutation mutation : mutations) {
            // Wrapper companions bind at their wrapper entry, not the original
            // owner's initializer (which may not declare any native methods).
            if (!(mutation instanceof Direct)) continue;
            final ClassNode owner = mutation.method().owner;
            if (!initialized.add(owner) || isSelectedClassInitializer(mutation)) {
                continue;
            }
            final org.objectweb.asm.tree.MethodNode initializer = owner.node.methods.stream()
                    .filter(method -> "<clinit>".equals(method.name) && "()V".equals(method.desc))
                    .findFirst().orElse(null);
            if (initializer == null) {
                final org.objectweb.asm.tree.MethodNode created = new org.objectweb.asm.tree.MethodNode(
                        Opcodes.ASM9, Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
                created.instructions.add(loaderBinding(loaderName, owner));
                created.instructions.add(new org.objectweb.asm.tree.InsnNode(Opcodes.RETURN));
                created.maxStack = 1;
                owner.addMethod(new MethodNode(created, owner));
            } else {
                initializer.instructions.insert(loaderBinding(loaderName, owner));
                initializer.maxStack = Math.max(initializer.maxStack, 1);
            }
        }
    }

    private static void applyMutation(final Mutation mutation, final String loaderName) {
        if (mutation instanceof JavaCopy) return;
        if (mutation instanceof Remove removed) {
            removed.method().owner.getMethods().remove(removed.method());
            removed.method().owner.node.methods.remove(removed.method().node);
            return;
        }
        if (mutation instanceof Direct direct) {
            clearCode(direct.method().node);
            direct.method().node.access = (direct.method().node.access
                    & ~(Opcodes.ACC_ABSTRACT)) | Opcodes.ACC_NATIVE;
            removeNativeAnnotation(direct.method().node);
            return;
        }
        final Wrapper wrapper = (Wrapper) mutation;
        final org.objectweb.asm.tree.MethodNode replacement = cloneMethod(wrapper.wrapperTemplate());
        replacement.instructions.insert(loaderBinding(loaderName, wrapper.helperOwner()));
        replacement.maxStack = Math.max(replacement.maxStack, 1);
        replaceCode(wrapper.method().node, replacement);
        wrapper.method().node.access &= ~(Opcodes.ACC_NATIVE | Opcodes.ACC_ABSTRACT);
        removeNativeAnnotation(wrapper.method().node);
        wrapper.helperOwner().addMethod(new MethodNode(cloneMethod(wrapper.nativeHelper()), wrapper.helperOwner()));
    }

    private static InsnList loaderBinding(final String loaderName, final ClassNode owner) {
        final InsnList instructions = new InsnList();
        instructions.add(new org.objectweb.asm.tree.LdcInsnNode(Type.getObjectType(owner.getName())));
        instructions.add(new MethodInsnNode(Opcodes.INVOKESTATIC, loaderName,
                "ensureBound", "(Ljava/lang/Class;)V", false));
        return instructions;
    }

    private static void clearCode(final org.objectweb.asm.tree.MethodNode method) {
        method.instructions.clear();
        if (method.tryCatchBlocks != null) {
            method.tryCatchBlocks.clear();
        }
        method.localVariables = null;
        method.visibleLocalVariableAnnotations = null;
        method.invisibleLocalVariableAnnotations = null;
        if (method.attrs != null) {
            method.attrs = method.attrs.stream().filter(attribute -> !attribute.isCodeAttribute())
                    .collect(java.util.stream.Collectors.toCollection(ArrayList::new));
        }
        method.maxStack = 0;
        method.maxLocals = 0;
    }

    private static void replaceCode(
            final org.objectweb.asm.tree.MethodNode destination,
            final org.objectweb.asm.tree.MethodNode source
    ) {
        destination.instructions = source.instructions;
        destination.tryCatchBlocks = source.tryCatchBlocks;
        destination.localVariables = source.localVariables;
        destination.visibleLocalVariableAnnotations = source.visibleLocalVariableAnnotations;
        destination.invisibleLocalVariableAnnotations = source.invisibleLocalVariableAnnotations;
        destination.maxStack = source.maxStack;
        destination.maxLocals = source.maxLocals;
        if (destination.attrs != null) {
            destination.attrs = destination.attrs.stream().filter(attribute -> !attribute.isCodeAttribute())
                    .collect(java.util.stream.Collectors.toCollection(ArrayList::new));
        }
    }

    private static void removeNativeAnnotation(final org.objectweb.asm.tree.MethodNode method) {
        method.visibleAnnotations = withoutNativeAnnotation(method.visibleAnnotations);
        method.invisibleAnnotations = withoutNativeAnnotation(method.invisibleAnnotations);
    }

    private static List<AnnotationNode> withoutNativeAnnotation(final List<AnnotationNode> annotations) {
        if (annotations == null) {
            return null;
        }
        final List<AnnotationNode> retained = annotations.stream()
                .filter(annotation -> !NATIVE_ANNOTATION.equals(annotation.desc))
                .collect(java.util.stream.Collectors.toCollection(ArrayList::new));
        return retained.isEmpty() ? null : retained;
    }

    private static org.objectweb.asm.tree.MethodNode cloneMethod(
            final org.objectweb.asm.tree.MethodNode source
    ) {
        final org.objectweb.asm.tree.MethodNode copy = new org.objectweb.asm.tree.MethodNode(
                Opcodes.ASM9,
                source.access,
                source.name,
                source.desc,
                source.signature,
                source.exceptions == null ? null : source.exceptions.toArray(String[]::new)
        );
        source.accept(copy);
        return copy;
    }

    private static Map<org.objectweb.asm.tree.MethodNode, MethodSnapshot> snapshots(
            final List<Mutation> mutations
    ) {
        final Map<org.objectweb.asm.tree.MethodNode, MethodSnapshot> snapshots = new IdentityHashMap<>();
        for (final Mutation mutation : mutations) {
            snapshots.putIfAbsent(mutation.method().node,
                    new MethodSnapshot(cloneMethod(mutation.method().node)));
            // installInitialization also mutates existing initializers. Merely restoring
            // the owner's method lists does not undo edits to these shared MethodNodes.
            for (final org.objectweb.asm.tree.MethodNode method : mutation.method().owner.node.methods) {
                if ("<clinit>".equals(method.name) && "()V".equals(method.desc)) {
                    snapshots.putIfAbsent(method, new MethodSnapshot(cloneMethod(method)));
                }
            }
        }
        return snapshots;
    }

    private static Map<ClassNode, ClassSnapshot> ownerSnapshots(
            final List<Mutation> mutations,
            final List<JavaLinkageHelper> linkageHelpers
    ) {
        final Map<ClassNode, ClassSnapshot> snapshots = new IdentityHashMap<>();
        for (final Mutation mutation : mutations) {
            snapshots.putIfAbsent(mutation.method().owner, new ClassSnapshot(mutation.method().owner));
            if (mutation instanceof Wrapper wrapper) {
                snapshots.putIfAbsent(wrapper.helperOwner(), new ClassSnapshot(wrapper.helperOwner()));
            }
        }
        for (final JavaLinkageHelper helper : linkageHelpers) {
            snapshots.putIfAbsent(helper.owner(), new ClassSnapshot(helper.owner()));
        }
        return snapshots;
    }

    private static void restoreMethods(
            final Map<org.objectweb.asm.tree.MethodNode, MethodSnapshot> snapshots
    ) {
        for (final Map.Entry<org.objectweb.asm.tree.MethodNode, MethodSnapshot> entry : snapshots.entrySet()) {
            entry.getValue().restore(entry.getKey());
        }
    }

    private static void restoreOwners(final Map<ClassNode, ClassSnapshot> snapshots) {
        for (final Map.Entry<ClassNode, ClassSnapshot> entry : snapshots.entrySet()) {
            entry.getValue().restore(entry.getKey());
        }
    }

    private static void validateLoaderCollision(final JarContents contents, final String loaderName) {
        final String path = loaderName + ".class";
        if (contents.getClassContents().stream().anyMatch(data -> path.equals(data.getName())
                || loaderName.equals(data.getClassNode().getName()))
                || contents.getResourceContents().stream().anyMatch(resource -> path.equals(resource.getName()))) {
            throw new IllegalStateException("Generated native loader collides with destination entry: " + path);
        }
    }

    private static boolean isSelectedClassInitializer(final Mutation mutation) {
        return mutation instanceof Wrapper && mutation.method().isClinit();
    }

    public sealed interface Mutation permits Direct, Wrapper, JavaCopy, Remove {
        MethodNode method();
    }

    /** A native implementation exists, but Java continues to execute this exact body. */
    public record JavaCopy(MethodNode method) implements Mutation {
        public JavaCopy { Objects.requireNonNull(method, "method"); }
    }

    /** The entry policy and LLVM verifier proved that no Java dispatch needs this declaration. */
    public record Remove(MethodNode method, boolean reviewedClosedWorld) implements Mutation {
        public Remove(MethodNode method) { this(method, false); }
        public Remove { Objects.requireNonNull(method, "method"); }
    }

    public record Direct(MethodNode method) implements Mutation {
        public Direct {
            Objects.requireNonNull(method, "method");
        }
    }

    /**
     * A prepared wrapper transaction. The template owns the exact semantic bridge code; this
     * transaction prepends loader initialization and installs the code-free native helper.
     */
    public record Wrapper(
            MethodNode method,
            ClassNode helperOwner,
            org.objectweb.asm.tree.MethodNode nativeHelper,
            org.objectweb.asm.tree.MethodNode wrapperTemplate
    ) implements Mutation {
        public Wrapper {
            Objects.requireNonNull(method, "method");
            Objects.requireNonNull(helperOwner, "helperOwner");
            Objects.requireNonNull(nativeHelper, "nativeHelper");
            Objects.requireNonNull(wrapperTemplate, "wrapperTemplate");
        }
    }

    @FunctionalInterface
    public interface ResourceStager {
        List<String> stage(JarContents contents) throws IOException;
    }

    public record CommitResult(String loaderInternalName, List<String> resources, int methodCount) {
        public CommitResult {
            Objects.requireNonNull(loaderInternalName, "loaderInternalName");
            resources = List.copyOf(Objects.requireNonNull(resources, "resources"));
            if (methodCount <= 0) {
                throw new IllegalArgumentException("methodCount must be positive");
            }
        }
    }

    private record MethodSnapshot(org.objectweb.asm.tree.MethodNode copy) {
        private void restore(final org.objectweb.asm.tree.MethodNode destination) {
            destination.access = copy.access;
            destination.name = copy.name;
            destination.desc = copy.desc;
            destination.signature = copy.signature;
            destination.exceptions = copy.exceptions;
            destination.parameters = copy.parameters;
            destination.annotationDefault = copy.annotationDefault;
            destination.visibleAnnotations = copy.visibleAnnotations;
            destination.invisibleAnnotations = copy.invisibleAnnotations;
            destination.visibleTypeAnnotations = copy.visibleTypeAnnotations;
            destination.invisibleTypeAnnotations = copy.invisibleTypeAnnotations;
            destination.visibleAnnotableParameterCount = copy.visibleAnnotableParameterCount;
            destination.visibleParameterAnnotations = copy.visibleParameterAnnotations;
            destination.invisibleAnnotableParameterCount = copy.invisibleAnnotableParameterCount;
            destination.invisibleParameterAnnotations = copy.invisibleParameterAnnotations;
            destination.attrs = copy.attrs;
            destination.instructions = copy.instructions;
            destination.tryCatchBlocks = copy.tryCatchBlocks;
            destination.maxStack = copy.maxStack;
            destination.maxLocals = copy.maxLocals;
            destination.localVariables = copy.localVariables;
            destination.visibleLocalVariableAnnotations = copy.visibleLocalVariableAnnotations;
            destination.invisibleLocalVariableAnnotations = copy.invisibleLocalVariableAnnotations;
        }
    }

    private record ClassSnapshot(List<MethodNode> methods, List<org.objectweb.asm.tree.MethodNode> asmMethods,
                                 List<org.mapleir.asm.FieldNode> fields, List<org.objectweb.asm.tree.FieldNode> asmFields) {
        private ClassSnapshot(final ClassNode owner) {
            this(new ArrayList<>(owner.getMethods()), new ArrayList<>(owner.node.methods),
                    new ArrayList<>(owner.getFields()),new ArrayList<>(owner.node.fields));
        }

        private void restore(final ClassNode owner) {
            owner.getMethods().clear();
            owner.getMethods().addAll(methods);
            owner.node.methods.clear();
            owner.node.methods.addAll(asmMethods);
            owner.getFields().clear();owner.getFields().addAll(fields);
            owner.node.fields.clear();owner.node.fields.addAll(asmFields);
        }
    }
}
