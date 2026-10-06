package dev.skidfuscator.test.nativebackend;

import com.typesafe.config.ConfigFactory;
import dev.skidfuscator.config.nativeobfuscation.NativeConfig;
import dev.skidfuscator.config.nativeobfuscation.NativeMode;
import dev.skidfuscator.obfuscator.nativebackend.selection.NativeCandidateSelector;
import dev.skidfuscator.obfuscator.nativebackend.selection.NativeSelection;
import dev.skidfuscator.obfuscator.nativebackend.selection.NativeSelectionSource;
import org.junit.jupiter.api.Test;
import org.mapleir.asm.ClassNode;
import org.mapleir.asm.MethodNode;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AnnotationNode;

import java.util.ArrayList;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class NativeCandidateSelectorTest {
    private static final String ANNOTATION = "Ldev/skidfuscator/annotations/NativeObfuscation;";
    private static final String MODE = "Ldev/skidfuscator/annotations/NativeObfuscation$Mode;";

    @Test
    void appliesDocumentedPrecedence() {
        NativeCandidateSelector selector = selector("""
                native {
                  enabled = true
                  defaultMode = AOT
                  exempt = ["class{^demo/Exempt$}"]
                  "include" = ["method{included}"]
                  rules = [
                    { match = "method{selected}", mode = AOT },
                    { match = "class{^demo/Target$} method{selected}", mode = VM }
                  ]
                }
                """);

        MethodNode explicit = method("demo/Target", "explicit");
        annotate(explicit, "AOT");
        assertSelection(selector, explicit, NativeMode.AOT, NativeSelectionSource.ANNOTATION_EXPLICIT, true);

        MethodNode rule = method("demo/Target", "selected");
        assertSelection(selector, rule, NativeMode.VM, NativeSelectionSource.RULE, false);

        MethodNode marker = method("demo/Target", "marker");
        annotate(marker, null);
        assertSelection(selector, marker, NativeMode.AOT, NativeSelectionSource.ANNOTATION_DEFAULT, true);

        MethodNode include = method("demo/Other", "included");
        assertSelection(selector, include, NativeMode.AOT, NativeSelectionSource.INCLUDE, false);

        MethodNode exempt = method("demo/Exempt", "included");
        annotate(exempt, "VM");
        assertFalse(selector.select(exempt).isPresent());
    }

    @Test
    void disabledConfigurationSelectsNothing() {
        NativeCandidateSelector selector = selector("native.enabled = false");
        MethodNode method = method("demo/Target", "selected");
        annotate(method, "VM");
        assertTrue(selector.select(method).isEmpty());
    }

    @Test
    void defaultAnnotationRemainsStrictWhenARuleChoosesTheMode() {
        final var selector = selector("""
                native { enabled = true, rules = [{ match = "method{selected}", mode = VM }] }
                """);
        final MethodNode selected = method("demo/Target", "selected");
        annotate(selected, null);
        assertSelection(selector, selected, NativeMode.VM, NativeSelectionSource.RULE, true);
    }

    @Test
    void keyOnlyModeSuppressesAllApplicationBodySelections() {
        final var selector = selector("""
                native {
                  enabled = true
                  threadedKey { enabled = true, only = true, mode = VM }
                  "include" = ["method{included}"]
                  rules = [{ match = "method{selected}", mode = VM }]
                }
                """);
        final MethodNode annotated = method("demo/Target", "annotated");
        annotate(annotated, "VM");
        assertTrue(selector.select(annotated).isEmpty());
        assertTrue(selector.select(method("demo/Target", "selected")).isEmpty());
        assertTrue(selector.select(method("demo/Target", "included")).isEmpty());
    }

    private static void assertSelection(NativeCandidateSelector selector,
                                        MethodNode method,
                                        NativeMode mode,
                                        NativeSelectionSource source,
                                        boolean strict) {
        Optional<NativeSelection> selected = selector.select(method);
        assertTrue(selected.isPresent());
        assertEquals(mode, selected.get().getMode());
        assertEquals(source, selected.get().getSource());
        assertEquals(strict, selected.get().isStrict());
    }

    private static NativeCandidateSelector selector(String hocon) {
        return new NativeCandidateSelector(new NativeConfig(ConfigFactory.parseString(hocon), "native"));
    }

    private static MethodNode method(String owner, String name) {
        ClassNode classNode = new ClassNode();
        classNode.node.name = owner;
        classNode.node.access = Opcodes.ACC_PUBLIC;
        org.objectweb.asm.tree.MethodNode asm = new org.objectweb.asm.tree.MethodNode(
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                name,
                "()I",
                null,
                null
        );
        MethodNode method = new MethodNode(asm, classNode);
        classNode.addMethod(method);
        return method;
    }

    private static void annotate(MethodNode method, String mode) {
        AnnotationNode annotation = new AnnotationNode(ANNOTATION);
        if (mode != null) {
            annotation.values = new ArrayList<>();
            annotation.values.add("mode");
            annotation.values.add(new String[]{MODE, mode});
        }
        method.node.invisibleAnnotations = new ArrayList<>();
        method.node.invisibleAnnotations.add(annotation);
    }
}
