package dev.skidfuscator.obfuscator.creator;

import com.typesafe.config.ConfigFactory;
import dev.skidfuscator.obfuscator.Skidfuscator;
import dev.skidfuscator.obfuscator.compatibility.RuntimeContractRegistry;
import dev.skidfuscator.obfuscator.skidasm.SkidGroup;
import dev.skidfuscator.obfuscator.transform.impl.annotation.IntAnnotationEncryptionTransformer;
import dev.skidfuscator.obfuscator.transform.impl.annotation.StringAnnotationEncryptionTransformer;
import dev.skidfuscator.obfuscator.transform.impl.method.MethodMergeTransformer;
import dev.skidfuscator.obfuscator.transform.impl.signature.SignatureObfuscationTransformer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;
import org.topdank.byteengineer.commons.data.JarClassData;
import org.topdank.byteengineer.commons.data.JarContents;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class RuntimeContractRegistryTest implements Opcodes {
    @TempDir Path directory;

    @Test void preservesCallbackAbisWithoutExemptingTheirBodiesOrPrivateHelpers() {
        ClassNode hook = owner("fixture/Hook");
        MethodNode shadow = method(hook, ACC_PUBLIC, "shadow", "()V");
        shadow.invisibleAnnotations = List.of(new AnnotationNode("Lorg/spongepowered/asm/mixin/Shadow;"));
        MethodNode callback = method(hook, ACC_PRIVATE, "hook", "()V");
        callback.visibleAnnotations = List.of(new AnnotationNode("Lorg/spongepowered/asm/mixin/injection/Inject;"));
        MethodNode event = method(hook, ACC_PUBLIC, "event", "()V");
        event.visibleAnnotations = List.of(new AnnotationNode("Lnet/minecraftforge/fml/common/eventhandler/SubscribeEvent;"));
        MethodNode helper = method(hook, ACC_PRIVATE | ACC_STATIC, "helper", "(I)I");
        RuntimeContractRegistry registry = registry(List.of(hook), RuntimeContractRegistry.Options.defaults());
        assertTrue(registry.isMethodContract(shadow));
        assertTrue(registry.isMethodContract(callback));
        assertTrue(registry.isMethodContract(event));
        assertFalse(registry.isMethodContract(helper));
        callback.instructions.add(new InsnNode(NOP));
        helper.desc = "(J)J";
        assertDoesNotThrow(registry::validate, "Body changes and noncontract descriptors remain legal");
        callback.desc = "(I)V";
        assertThrows(IllegalStateException.class, registry::validate);
    }

    @Test void pinsEnumNativeAndProtobufReflectionIncludingPrivateSetters() {
        ClassNode enumeration = owner("fixture/Choice");
        enumeration.access |= ACC_ENUM;
        enumeration.superName = "java/lang/Enum";
        MethodNode values = method(enumeration, ACC_PUBLIC | ACC_STATIC, "values", "()[Lfixture/Choice;");
        MethodNode valueOf = method(enumeration, ACC_PUBLIC | ACC_STATIC, "valueOf", "(Ljava/lang/String;)Lfixture/Choice;");
        MethodNode enumHelper = method(enumeration, ACC_PRIVATE | ACC_STATIC, "helper", "()V");
        ClassNode exports = owner("fixture/Kernel");
        exports.access |= ACC_INTERFACE | ACC_ABSTRACT;
        exports.interfaces.add("com/sun/jna/Library");
        MethodNode query = method(exports, ACC_PUBLIC | ACC_ABSTRACT, "GetCurrentProcess", "()J");
        ClassNode structure = owner("fixture/Info");
        structure.superName = "com/sun/jna/Structure";
        FieldNode field = new FieldNode(ACC_PUBLIC, "BaseAddress", "J", null, null);
        structure.fields.add(field);
        MethodNode order = method(structure, ACC_PROTECTED, "getFieldOrder", "()Ljava/util/List;");
        ClassNode proto = owner("fixture/Message");
        proto.superName = "com/google/protobuf/GeneratedMessageLite";
        MethodNode factory = method(proto, ACC_PUBLIC | ACC_STATIC, "newBuilder", "()Ljava/lang/Object;");
        MethodNode privateSetter = method(proto, ACC_PRIVATE, "setName", "(Ljava/lang/String;)V");
        RuntimeContractRegistry registry = registry(List.of(enumeration, exports, structure, proto), RuntimeContractRegistry.Options.defaults());
        for (MethodNode contract : List.of(values, valueOf, query, order, factory)) assertTrue(registry.isMethodContract(contract));
        assertTrue(registry.isFieldContract(field));
        assertTrue(registry.isMethodContract(privateSetter));
        assertFalse(registry.isMethodContract(enumHelper));
        field.name = "renamedLayoutField";
        assertThrows(IllegalStateException.class, registry::validate);
    }

    @Test void exactContractsFollowBothRenamedOwnersAndPrivateMemberNames() throws Exception {
        ClassNode type = owner("x/C1");
        MethodNode contract = method(type, ACC_PRIVATE | ACC_STATIC, "o$7", "(Lx/C1;)Lx/C1;");
        MethodNode api = method(type, ACC_PUBLIC | ACC_STATIC, "publicApi", "()V");
        MethodNode helper = method(type, ACC_PRIVATE | ACC_STATIC, "o$8", "()V");
        Map<String, String> names = Map.of("fixture/api/Before", type.name,
                "fixture/api/Before.secret(Lfixture/api/Before;)Lfixture/api/Before;", "o$7");
        RuntimeContractRegistry registry = registry(List.of(type), new RuntimeContractRegistry.Options(
                List.of("fixture/api/Before#secret(Lfixture/api/Before;)Lfixture/api/Before;"),
                List.of(), List.of("fixture/api"), names));
        assertTrue(registry.isMethodContract(contract));
        assertTrue(registry.isMethodContract(api));
        assertFalse(registry.isMethodContract(helper));
        registry.writeReport(directory.resolve("contracts.tsv"));
        assertTrue(Files.readString(directory.resolve("contracts.tsv")).contains("x/C1#o$7(Lx/C1;)Lx/C1;"));
        assertThrows(IllegalArgumentException.class, () -> registry(List.of(type), new RuntimeContractRegistry.Options(
                List.of("fixture/api/Before#missing()V"), List.of(), List.of(), names)));
    }

    @Test void conservativeLiteralReflectionPinsNamesAndReportsUnresolvedDiscovery() throws Exception {
        ClassNode type = owner("fixture/Reflection");
        MethodNode reflected = method(type, ACC_PRIVATE | ACC_STATIC, "sendVerified", "()V");
        MethodNode helper = method(type, ACC_PRIVATE | ACC_STATIC, "other", "()V");
        MethodNode probe = method(type, ACC_PUBLIC | ACC_STATIC, "probe", "()V");
        probe.instructions.add(new LdcInsnNode("sendVerified"));
        probe.instructions.add(new MethodInsnNode(INVOKEVIRTUAL, "java/lang/Class", "getDeclaredMethod",
                "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;", false));
        MethodNode discover = method(type, ACC_PUBLIC | ACC_STATIC, "discover", "()V");
        discover.instructions.add(new MethodInsnNode(INVOKEVIRTUAL, "java/lang/Class", "getDeclaredMethods",
                "()[Ljava/lang/reflect/Method;", false));
        RuntimeContractRegistry registry = registry(List.of(type), RuntimeContractRegistry.Options.defaults());
        assertTrue(registry.isMethodContract(reflected));
        assertFalse(registry.isMethodContract(helper), "Enumeration is reported, not falsely treated as fully resolved");
        registry.writeReport(directory.resolve("reflection.tsv"));
        assertTrue(Files.readString(directory.resolve("reflection.tsv")).contains("REVIEW_REFLECTION\tfixture/Reflection#discover"));
    }

    @Test void validatesFieldValuesAndMetadataWithoutFreezingAllAnnotationElements() {
        ClassNode annotation = annotation("fixture/Metadata");
        MethodNode stable = method(annotation, ACC_PUBLIC | ACC_ABSTRACT, "profileKey", "()Ljava/lang/String;");
        stable.annotationDefault = "default-profile";
        method(annotation, ACC_PUBLIC | ACC_ABSTRACT, "display", "()Ljava/lang/String;");
        ClassNode type = owner("fixture/Module");
        FieldNode field = new FieldNode(ACC_PUBLIC | ACC_STATIC | ACC_FINAL, "VERSION", "Ljava/lang/String;", null, "1.0");
        type.fields.add(field);
        AnnotationNode metadata = new AnnotationNode("Lfixture/Metadata;");
        metadata.values = new ArrayList<>(List.of("profileKey", "stable", "display", "visible"));
        type.visibleAnnotations = List.of(metadata);
        RuntimeContractRegistry registry = registry(List.of(annotation, type), new RuntimeContractRegistry.Options(
                List.of(), List.of("fixture/Metadata#profileKey"), List.of(), Map.of()));
        assertTrue(registry.isAnnotationElementContract(metadata.desc, "profileKey"));
        assertFalse(registry.isAnnotationElementContract(metadata.desc, "display"));
        metadata.values.set(3, "encoded-display");
        assertDoesNotThrow(registry::validate);
        metadata.values.set(1, "broken-profile");
        assertThrows(IllegalStateException.class, registry::validate);
        metadata.values.set(1, "stable");
        field.value = null;
        assertThrows(IllegalStateException.class, registry::validate);
        field.value = "1.0";
        stable.annotationDefault = "broken-default";
        assertThrows(IllegalStateException.class, registry::validate);
    }

    @Test void actualAnnotationPassesPreserveContractValuesAndStillEncryptOtherElements() throws Exception {
        ClassNode annotation = annotation("fixture/MetadataPass");
        MethodNode stableText = method(annotation, ACC_PUBLIC | ACC_ABSTRACT, "profileKey", "()Ljava/lang/String;");
        stableText.annotationDefault = "stable-default";
        MethodNode secretText = method(annotation, ACC_PUBLIC | ACC_ABSTRACT, "display", "()Ljava/lang/String;");
        secretText.annotationDefault = "secret-default";
        MethodNode stableInt = method(annotation, ACC_PUBLIC | ACC_ABSTRACT, "revision", "()I");
        stableInt.annotationDefault = 41;
        MethodNode secretInt = method(annotation, ACC_PUBLIC | ACC_ABSTRACT, "internal", "()I");
        secretInt.annotationDefault = 73;
        ClassNode owner = owner("fixture/AnnotationConsumer");
        AnnotationNode value = new AnnotationNode("Lfixture/MetadataPass;");
        value.values = new ArrayList<>(List.of("profileKey", "stable-value", "display", "secret-value", "revision", 41, "internal", 73));
        owner.visibleAnnotations = List.of(value);
        MethodNode reader = method(owner, ACC_PUBLIC | ACC_STATIC, "read", "()V");
        MethodInsnNode stableCall = new MethodInsnNode(INVOKEINTERFACE, annotation.name, "revision", "()I", true);
        MethodInsnNode secretCall = new MethodInsnNode(INVOKEINTERFACE, annotation.name, "internal", "()I", true);
        // These instruction fragments exercise accessor rewriting only; executable
        // annotation pass behavior is covered by the repository's own fixtures.
        reader.instructions.add(stableCall);
        reader.instructions.add(new InsnNode(POP));
        reader.instructions.add(secretCall);
        reader.instructions.add(new InsnNode(POP));
        RuntimeContractRegistry registry = registry(List.of(annotation, owner), new RuntimeContractRegistry.Options(
                List.of(), List.of("fixture/MetadataPass#profileKey", "fixture/MetadataPass#revision"), List.of(), Map.of()));
        Skidfuscator skid = skid(List.of(annotation, owner), registry);
        StringAnnotationEncryptionTransformer strings = new StringAnnotationEncryptionTransformer(skid);
        IntAnnotationEncryptionTransformer integers = new IntAnnotationEncryptionTransformer(skid);
        strings.apply();
        integers.apply();
        assertEquals("stable-value", value.values.get(1));
        assertNotEquals("secret-value", value.values.get(3));
        assertEquals(41, value.values.get(5));
        assertNotEquals(73, value.values.get(7));
        assertEquals("stable-default", stableText.annotationDefault);
        assertNotEquals("secret-default", secretText.annotationDefault);
        assertEquals(41, stableInt.annotationDefault);
        assertNotEquals(73, secretInt.annotationDefault);
        assertEquals(POP, stableCall.getNext().getOpcode(), "Preserved integers must not be spuriously decrypted");
        assertNotEquals(POP, secretCall.getNext().getOpcode(), "Eligible integer accessors must still decrypt");
        Method accessor = StringAnnotationEncryptionTransformer.class.getDeclaredMethod("isAnnotationAccessor", MethodInsnNode.class);
        accessor.setAccessible(true);
        assertEquals(false, accessor.invoke(strings, new MethodInsnNode(INVOKEINTERFACE, annotation.name, "profileKey", "()Ljava/lang/String;", true)));
        assertEquals(true, accessor.invoke(strings, new MethodInsnNode(INVOKEINTERFACE, annotation.name, "display", "()Ljava/lang/String;", true)));
        assertDoesNotThrow(registry::validate);
    }

    @Test void productionSignatureAndMergeSelectionHonorContractsNotBodyExemptions() throws Exception {
        ClassNode owner = owner("fixture/Callable");
        MethodNode guarded = method(owner, ACC_PRIVATE | ACC_STATIC, "reflective", "(I)I");
        MethodNode eligible = method(owner, ACC_PRIVATE | ACC_STATIC, "ordinary", "(I)I");
        for (MethodNode method : List.of(guarded, eligible)) {
            method.instructions.add(new VarInsnNode(ILOAD, 0));
            method.instructions.add(new InsnNode(IRETURN));
            method.maxLocals = 1;
            method.maxStack = 1;
        }
        RuntimeContractRegistry registry = registry(List.of(owner), new RuntimeContractRegistry.Options(
                List.of(owner.name + "#reflective(I)I"), List.of(), List.of(), Map.of()));
        Skidfuscator skid = skid(List.of(owner), registry);
        SignatureObfuscationTransformer signature = new SignatureObfuscationTransformer(skid);
        Class<?> keyType = Arrays.stream(SignatureObfuscationTransformer.class.getDeclaredClasses())
                .filter(c -> c.getSimpleName().equals("MethodKey")).findFirst().orElseThrow();
        Constructor<?> constructor = keyType.getDeclaredConstructor(String.class, String.class, String.class);
        constructor.setAccessible(true);
        Method candidate = SignatureObfuscationTransformer.class.getDeclaredMethod("buildCandidate", keyType, MethodNode.class,
                Map.class, Set.class, Map.class, Set.class, boolean.class, boolean.class, boolean.class);
        candidate.setAccessible(true);
        for (MethodNode method : List.of(guarded, eligible)) {
            Object key = constructor.newInstance(owner.name, method.name, method.desc);
            Object result = candidate.invoke(signature, key, method, Map.of(owner.name, owner), Set.of(), Map.of(key, 1), Set.of(), true, true, false);
            if (method == guarded) assertNull(result);
            else assertNotNull(result, "A private noncontract implementation must remain eligible for signature obfuscation");
        }
        org.mapleir.asm.ClassNode wrapper = new org.mapleir.asm.ClassNode();
        wrapper.node = owner;
        org.mapleir.asm.MethodNode method = new org.mapleir.asm.MethodNode(guarded, wrapper);
        SkidGroup group = mock(SkidGroup.class);
        when(group.isInjectedMethodPredicate()).thenReturn(true);
        when(group.getMethodNodeList()).thenReturn(List.of(method));
        when(group.first()).thenReturn(method);
        MethodMergeTransformer merge = new MethodMergeTransformer(skid);
        Method mergeCandidate = MethodMergeTransformer.class.getDeclaredMethod("toCandidate", SkidGroup.class, Set.class);
        mergeCandidate.setAccessible(true);
        assertNull(mergeCandidate.invoke(merge, group, Set.of()));
        assertFalse(skid.getExemptAnalysis().isExempt(method), "The contract never becomes a body exemption");
    }

    private static RuntimeContractRegistry registry(List<ClassNode> nodes, RuntimeContractRegistry.Options options) {
        Map<String, ClassNode> classes = new LinkedHashMap<>();
        nodes.forEach(node -> classes.put(node.name, node));
        return new RuntimeContractRegistry(classes, classes.keySet(), classes::get, options);
    }

    private static Skidfuscator skid(List<ClassNode> nodes, RuntimeContractRegistry registry) {
        Skidfuscator skid = mock(Skidfuscator.class, RETURNS_DEEP_STUBS);
        when(skid.getTsConfig()).thenReturn(ConfigFactory.empty());
        when(skid.isRuntimeContract(any(MethodNode.class))).thenAnswer(call -> registry.isMethodContract(call.getArgument(0)));
        when(skid.isRuntimeContract(any(org.mapleir.asm.MethodNode.class))).thenAnswer(call -> registry.isMethodContract(((org.mapleir.asm.MethodNode) call.getArgument(0)).node));
        when(skid.isAnnotationElementContract(anyString(), anyString())).thenAnswer(call -> registry.isAnnotationElementContract(call.getArgument(0), call.getArgument(1)));
        JarContents contents = new JarContents();
        Map<String, org.mapleir.asm.ClassNode> wrappers = new HashMap<>();
        for (ClassNode node : nodes) {
            org.mapleir.asm.ClassNode wrapper = new org.mapleir.asm.ClassNode();
            wrapper.node = node;
            for (MethodNode method : node.methods) wrapper.getMethods().add(new org.mapleir.asm.MethodNode(method, wrapper));
            for (FieldNode field : node.fields) wrapper.getFields().add(new org.mapleir.asm.FieldNode(field, wrapper));
            wrappers.put(node.name, wrapper);
            contents.getClassContents().add(new JarClassData(node.name + ".class", new byte[0], wrapper));
        }
        when(skid.getJarContents()).thenReturn(contents);
        when(skid.getClassSource().iterate()).thenReturn(wrappers.values());
        when(skid.getClassSource().findClassNode(anyString())).thenAnswer(call -> wrappers.get(call.getArgument(0)));
        return skid;
    }
    private static ClassNode owner(String name) {
        ClassNode node = new ClassNode();
        node.visit(V1_8, ACC_PUBLIC, name, null, "java/lang/Object", null);
        return node;
    }
    private static ClassNode annotation(String name) {
        ClassNode node = owner(name);
        node.access |= ACC_ANNOTATION | ACC_INTERFACE | ACC_ABSTRACT;
        node.interfaces.add("java/lang/annotation/Annotation");
        return node;
    }
    private static MethodNode method(ClassNode owner, int flags, String name, String desc) {
        MethodNode method = new MethodNode(flags, name, desc, null, null);
        owner.methods.add(method);
        return method;
    }
}
