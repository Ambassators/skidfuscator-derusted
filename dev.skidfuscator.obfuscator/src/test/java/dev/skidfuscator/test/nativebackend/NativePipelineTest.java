package dev.skidfuscator.test.nativebackend;

import com.typesafe.config.ConfigFactory;
import dev.skidfuscator.config.DefaultSkidConfig;
import dev.skidfuscator.config.nativeobfuscation.NativeMode;
import dev.skidfuscator.obfuscator.Skidfuscator;
import dev.skidfuscator.obfuscator.SkidfuscatorSession;
import dev.skidfuscator.obfuscator.creator.SkidApplicationClassSource;
import dev.skidfuscator.obfuscator.hierarchy.Hierarchy;
import dev.skidfuscator.obfuscator.nativebackend.NativeBackendUnavailableException;
import dev.skidfuscator.obfuscator.nativebackend.NativeCompilationPlan;
import dev.skidfuscator.obfuscator.nativebackend.NativeEligibility;
import dev.skidfuscator.obfuscator.nativebackend.NativePipeline;
import dev.skidfuscator.obfuscator.nativebackend.NativeSelectionException;
import dev.skidfuscator.obfuscator.nativebackend.selection.NativeSelection;
import dev.skidfuscator.obfuscator.nativebackend.selection.NativeSelectionSource;
import dev.skidfuscator.obfuscator.skidasm.SkidClassNode;
import dev.skidfuscator.obfuscator.skidasm.SkidGroup;
import dev.skidfuscator.obfuscator.skidasm.SkidMethodNode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.InsnNode;

import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class NativePipelineTest {
    @TempDir
    Path temporaryDirectory;

    @Test
    void disabledNativeModeIsANoOp() {
        Skidfuscator skidfuscator = mock(Skidfuscator.class);
        when(skidfuscator.getConfig()).thenReturn(config("native.enabled = false"));

        NativeCompilationPlan plan = new NativePipeline(skidfuscator).prepare();
        assertTrue(plan.candidates().isEmpty());
        assertTrue(plan.skipped().isEmpty());
    }

    @Test
    void rejectsDexBeforeTouchingMethods() {
        Skidfuscator skidfuscator = mock(Skidfuscator.class);
        SkidfuscatorSession session = mock(SkidfuscatorSession.class);
        when(skidfuscator.getConfig()).thenReturn(config("native.enabled = true"));
        when(skidfuscator.getSession()).thenReturn(session);
        when(session.isDex()).thenReturn(true);

        assertThrows(NativeSelectionException.class, () -> new NativePipeline(skidfuscator).prepare());
    }

    @Test
    void neverSilentlyEmitsJavaForAnEligibleSelectedMethod() {
        Skidfuscator skidfuscator = mock(Skidfuscator.class);
        SkidfuscatorSession session = mock(SkidfuscatorSession.class);
        Hierarchy hierarchy = mock(Hierarchy.class);
        SkidApplicationClassSource source = mock(SkidApplicationClassSource.class);
        SkidMethodNode method = method();
        when(skidfuscator.getConfig()).thenReturn(config("""
                native {
                  enabled = true
                  "include" = ["method{run}"]
                }
                """));
        when(skidfuscator.getSession()).thenReturn(session);
        when(skidfuscator.getHierarchy()).thenReturn(hierarchy);
        when(skidfuscator.getClassSource()).thenReturn(source);
        when(hierarchy.getMethods()).thenReturn(List.of(method));
        when(source.isApplicationClass("example/Owner")).thenReturn(true);

        assertThrows(
                NativeBackendUnavailableException.class,
                () -> new NativePipeline(skidfuscator).prepare()
        );
        assertTrue((method.node.access & Opcodes.ACC_NATIVE) == 0);
        assertTrue(method.node.instructions.size() > 0);
    }

    @Test
    void explicitBackendFailsWhenEveryMatcherSelectedMethodIsUnsupported() throws IOException {
        Skidfuscator skidfuscator = mock(Skidfuscator.class);
        SkidfuscatorSession session = mock(SkidfuscatorSession.class);
        Hierarchy hierarchy = mock(Hierarchy.class);
        SkidApplicationClassSource source = mock(SkidApplicationClassSource.class);
        SkidMethodNode method = method();
        method.node.access = Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC;
        // A void no-op now lowers through the isolated SSA builder. Use an actual
        // unsupported array-owner call to exercise rejection before toolchain setup.
        method.node.desc = "([I)Ljava/lang/Object;";
        method.node.instructions.clear();
        method.node.instructions.add(new org.objectweb.asm.tree.VarInsnNode(Opcodes.ALOAD, 0));
        method.node.instructions.add(new org.objectweb.asm.tree.MethodInsnNode(
                Opcodes.INVOKEVIRTUAL, "[I", "clone", "()Ljava/lang/Object;", false));
        method.node.instructions.add(new org.objectweb.asm.tree.InsnNode(Opcodes.ARETURN));
        method.node.maxLocals = 1;
        method.node.maxStack = 1;
        Path compiler = Files.createFile(temporaryDirectory.resolve("zig.exe"));
        when(skidfuscator.getConfig()).thenReturn(config("""
                native {
                  enabled = true
                  "include" = ["method{run}"]
                  targets = ["windows-x86_64"]
                  toolchain.delivery = EXTERNAL
                }
                """));
        when(skidfuscator.getSession()).thenReturn(session);
        when(session.getNativeToolchainPath()).thenReturn(compiler.toFile());
        when(skidfuscator.getHierarchy()).thenReturn(hierarchy);
        when(skidfuscator.getClassSource()).thenReturn(source);
        when(hierarchy.getMethods()).thenReturn(List.of(method));
        when(source.isApplicationClass("example/Owner")).thenReturn(true);

        NativeBackendUnavailableException failure = assertThrows(
                NativeBackendUnavailableException.class,
                () -> new NativePipeline(skidfuscator).prepare()
        );
        assertTrue(failure.getMessage().contains("None of the 1 selected method(s)"), failure.getMessage());
        assertTrue(failure.getMessage().contains("Rejections:"), failure.getMessage());
        assertTrue((method.node.access & Opcodes.ACC_NATIVE) == 0);
        assertTrue(method.node.instructions.size() > 0);
    }

    @Test
    void reservesBeforeTransformsAndRevalidatesTheSameMethodAfterward() {
        Skidfuscator skidfuscator = mock(Skidfuscator.class);
        SkidfuscatorSession session = mock(SkidfuscatorSession.class);
        Hierarchy hierarchy = mock(Hierarchy.class);
        SkidApplicationClassSource source = mock(SkidApplicationClassSource.class);
        SkidMethodNode method = method();
        when(skidfuscator.getConfig()).thenReturn(config("""
                native {
                  enabled = true
                  "include" = ["method{run}"]
                }
                """));
        when(skidfuscator.getSession()).thenReturn(session);
        when(skidfuscator.getHierarchy()).thenReturn(hierarchy);
        when(skidfuscator.getClassSource()).thenReturn(source);
        when(hierarchy.getMethods()).thenReturn(List.of(method));
        when(source.isApplicationClass("example/Owner")).thenReturn(true);

        NativePipeline pipeline = new NativePipeline(skidfuscator);
        NativeCompilationPlan reservation = pipeline.reserve();
        assertEquals(1, reservation.candidates().size());
        assertTrue(reservation.candidates().get(0).selection().getMethod() == method);

        // Simulates a structural transformer making the reserved method invalid.
        method.node.access |= Opcodes.ACC_NATIVE;
        NativeCompilationPlan finalized = pipeline.prepare(reservation);
        assertTrue(finalized.candidates().isEmpty());
        assertEquals(1, finalized.skipped().size());
        assertTrue(finalized.skipped().get(0).reason().contains("already native"));
    }

    @Test
    void reservedNativeIdentityProtectsItsMethodAndEntireTransformGroup() throws Exception {
        Skidfuscator skidfuscator = new Skidfuscator(mock(SkidfuscatorSession.class));
        SkidMethodNode reserved = method("reserved");
        SkidMethodNode ordinary = method("ordinary");
        NativeSelection selection = new NativeSelection(
                reserved,
                NativeMode.AOT,
                NativeSelectionSource.INCLUDE,
                false
        );
        NativeCompilationPlan plan = new NativeCompilationPlan(
                List.of(new NativeCompilationPlan.Candidate(
                        selection,
                        NativeEligibility.Conversion.DIRECT
                )),
                List.of()
        );
        Field planField = Skidfuscator.class.getDeclaredField("nativeCompilationPlan");
        planField.setAccessible(true);
        planField.set(skidfuscator, plan);

        SkidGroup reservedGroup = mock(SkidGroup.class);
        when(reservedGroup.getMethodNodeList()).thenReturn(List.of(ordinary, reserved));
        SkidGroup ordinaryGroup = mock(SkidGroup.class);
        when(ordinaryGroup.getMethodNodeList()).thenReturn(List.of(ordinary));

        assertTrue(skidfuscator.isNativeCandidate(reserved));
        assertTrue(skidfuscator.isNativeCandidate(reservedGroup));
        assertFalse(skidfuscator.isNativeCandidate(ordinary));
        assertFalse(skidfuscator.isNativeCandidate(ordinaryGroup));
    }

    @Test
    void keyOnlyRejectsMissingThreadedSitesWithoutSelectingApplicationBodies() {
        final Skidfuscator skid = mock(Skidfuscator.class);
        final SkidfuscatorSession session = mock(SkidfuscatorSession.class);
        final Hierarchy hierarchy = mock(Hierarchy.class);
        final SkidApplicationClassSource source = mock(SkidApplicationClassSource.class);
        final SkidMethodNode application = method();
        when(skid.getConfig()).thenReturn(config("""
                native {
                  enabled = true
                  "include" = ["method{run}"]
                  threadedKey { enabled = true, only = true, mode = VM }
                }
                """));
        when(skid.getSession()).thenReturn(session);
        when(skid.getHierarchy()).thenReturn(hierarchy);
        when(skid.getClassSource()).thenReturn(source);
        when(hierarchy.getMethods()).thenReturn(List.of(application));
        when(source.isApplicationClass("example/Owner")).thenReturn(true);
        when(skid.getNativeThreadedKeys()).thenReturn(
                new dev.skidfuscator.obfuscator.nativebackend.key.NativeThreadedKeyRegistry(skid));
        final NativePipeline pipeline = new NativePipeline(skid);
        final NativeCompilationPlan reservation = pipeline.reserve();
        assertTrue(reservation.candidates().isEmpty());
        final var failure = assertThrows(NativeSelectionException.class,
                () -> pipeline.prepare(reservation));
        assertTrue(failure.getMessage().contains("no eligible threaded seed sites"));
        assertFalse(application.isNative());
        assertEquals(1, application.node.instructions.size());
    }

    @Test
    void keyOnlyCannotFallBackToJavaWhenTheAuthenticatedToolchainIsMissing() throws IOException {
        final Skidfuscator skid = mock(Skidfuscator.class);
        final SkidfuscatorSession session = mock(SkidfuscatorSession.class);
        final Hierarchy hierarchy = mock(Hierarchy.class);
        final SkidApplicationClassSource source = mock(SkidApplicationClassSource.class);
        final SkidMethodNode application = method();
        final var contents = new org.topdank.byteengineer.commons.data.JarContents();
        when(skid.getConfig()).thenReturn(config("""
                native {
                  enabled = true
                  targets = ["windows-x86_64"]
                  toolchain.delivery = EXTERNAL
                  threadedKey { enabled = true, only = true, mode = VM }
                }
                """));
        when(skid.getSession()).thenReturn(session);
        when(session.getNativeToolchainPath()).thenReturn(
                Files.createDirectory(temporaryDirectory.resolve("missing-toolchain")).toFile());
        when(skid.getHierarchy()).thenReturn(hierarchy);
        when(skid.getClassSource()).thenReturn(source);
        when(skid.getJarContents()).thenReturn(contents);
        when(hierarchy.getMethods()).thenReturn(List.of(application));
        when(source.isApplicationClass("example/Owner")).thenReturn(true);
        final var keys = new dev.skidfuscator.obfuscator.nativebackend.key.NativeThreadedKeyRegistry(skid);
        when(skid.getNativeThreadedKeys()).thenReturn(keys);
        keys.reconstruct(application, false, 73, 27,
                new org.mapleir.ir.code.expr.ConstantExpr(27, org.objectweb.asm.Type.INT_TYPE));
        final NativePipeline pipeline = new NativePipeline(skid);
        final NativeCompilationPlan reservation = pipeline.reserve();
        assertTrue(reservation.candidates().isEmpty());
        assertThrows(NativeBackendUnavailableException.class, () -> pipeline.prepare(reservation));
        assertFalse(application.isNative());
        assertEquals(1, application.node.instructions.size());
        assertTrue(contents.getClassContents().isEmpty());
        assertTrue(contents.getResourceContents().isEmpty());
        assertFalse(keys.seal().get(0).method().isNative());
    }

    private static DefaultSkidConfig config(final String hocon) {
        return new DefaultSkidConfig(ConfigFactory.parseString(hocon), "");
    }

    private static SkidMethodNode method() {
        return method("run");
    }

    private static SkidMethodNode method(final String name) {
        org.objectweb.asm.tree.ClassNode rawOwner = new org.objectweb.asm.tree.ClassNode();
        rawOwner.name = "example/Owner";
        SkidClassNode owner = new SkidClassNode(rawOwner, null);
        org.objectweb.asm.tree.MethodNode raw = new org.objectweb.asm.tree.MethodNode(
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                name,
                "()V",
                null,
                null
        );
        raw.instructions.add(new InsnNode(Opcodes.RETURN));
        SkidMethodNode method = new SkidMethodNode(raw, owner, null);
        owner.addMethod(method);
        return method;
    }
}
