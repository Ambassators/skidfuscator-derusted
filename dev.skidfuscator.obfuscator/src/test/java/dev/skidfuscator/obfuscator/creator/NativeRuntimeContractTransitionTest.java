package dev.skidfuscator.obfuscator.creator;

import dev.skidfuscator.obfuscator.compatibility.RuntimeContractRegistry;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.MethodNode;
import java.util.List;
import java.util.Map;
import java.util.Set;
import static org.junit.jupiter.api.Assertions.*;

class NativeRuntimeContractTransitionTest implements Opcodes {
    @Test void acceptsOnlyAnExplicitCommittedImplementationTransition() {
        Fixture fixture = fixture();
        fixture.method.access |= ACC_NATIVE;
        fixture.method.instructions.clear();
        assertThrows(IllegalStateException.class, fixture.registry::validate);
        fixture.registry.recordCommittedNativeImplementation(fixture.method);
        assertDoesNotThrow(fixture.registry::validate);
        fixture.method.access &= ~ACC_NATIVE;
        assertThrows(IllegalStateException.class, fixture.registry::validate);
    }

    @Test void rejectsDescriptorAndVisibilityChangesDuringNativeCommit() {
        for (int change = 0; change < 3; change++) {
            Fixture fixture = fixture();
            fixture.method.access |= ACC_NATIVE;
            fixture.method.instructions.clear();
            if (change == 0) fixture.method.desc = "(I)I";
            if (change == 1) fixture.method.access = ACC_PRIVATE | ACC_STATIC | ACC_NATIVE;
            if (change == 2) fixture.method.access &= ~ACC_STATIC;
            assertThrows(IllegalStateException.class,
                    () -> fixture.registry.recordCommittedNativeImplementation(fixture.method));
            assertThrows(IllegalStateException.class, fixture.registry::validate);
        }
    }

    @Test void rejectsUncommittedBodyAndRemovedMethod() {
        Fixture fixture = fixture();
        fixture.method.access |= ACC_NATIVE;
        assertThrows(IllegalStateException.class,
                () -> fixture.registry.recordCommittedNativeImplementation(fixture.method));
        fixture.method.instructions.clear();
        fixture.owner.methods.remove(fixture.method);
        assertThrows(IllegalStateException.class,
                () -> fixture.registry.recordCommittedNativeImplementation(fixture.method));
    }

    @Test void cannotAuthorizeChangesToAnExistingNativeContract() {
        Fixture fixture = fixture();
        fixture.method.access |= ACC_NATIVE;
        fixture.method.instructions.clear();
        fixture.registry.recordCommittedNativeImplementation(fixture.method);
        assertThrows(IllegalStateException.class,
                () -> fixture.registry.recordCommittedNativeImplementation(fixture.method));
        assertDoesNotThrow(fixture.registry::validate);
    }

    private Fixture fixture() {
        ClassNode owner = new ClassNode();
        owner.visit(V1_8, ACC_PUBLIC | ACC_SUPER, "fixture/NativeAbi", null, "java/lang/Object", null);
        MethodNode method = new MethodNode(ACC_PUBLIC | ACC_STATIC, "value", "()I", null, null);
        method.instructions.add(new InsnNode(ICONST_1));
        method.instructions.add(new InsnNode(IRETURN));
        owner.methods.add(method);
        Map<String, ClassNode> classes = Map.of(owner.name, owner);
        RuntimeContractRegistry registry = new RuntimeContractRegistry(classes, Set.of(owner.name),
                classes::get, new RuntimeContractRegistry.Options(
                List.of(owner.name + "#value()I"), List.of(), List.of(), Map.of()));
        assertTrue(registry.isMethodContract(method));
        return new Fixture(owner, method, registry);
    }
    private record Fixture(ClassNode owner, MethodNode method, RuntimeContractRegistry registry) { }
}
