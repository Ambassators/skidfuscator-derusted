package dev.skidfuscator.nativetoolchain;

import dev.skidfuscator.nativeir.NativeBackend;
import dev.skidfuscator.nativeir.NativeBlock;
import dev.skidfuscator.nativeir.NativeFunction;
import dev.skidfuscator.nativeir.NativeIrVerifier;
import dev.skidfuscator.nativeir.NativeModule;
import dev.skidfuscator.nativeir.NativeTerminator;
import dev.skidfuscator.nativeir.NativeType;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

class ProcessNativeCompilerLocalAotTest {
    @TempDir Path directory;
    private static final NativeTarget HOST = NativeTarget.LINUX_X86_64;
    private static final String VERSION = "SkidLLVM 1.0.0-alpha.1 (LLVM 18.1.8, native IR ABI 1)\n";

    @Test void explicitLocalCompilationUsesRealDriverContractAndNeverRequestsVm() throws Exception {
        final AtomicInteger calls = new AtomicInteger();
        final ProcessNativeCompiler compiler = compiler((command, work, timeout) -> {
            calls.incrementAndGet();
            if (command.contains("--version")) return new ProcessExecutor.Result(0, false, VERSION);
            assertEquals("compile", command.get(1));
            assertFalse(command.stream().anyMatch(value -> value.startsWith("--vm-")));
            Files.write(Path.of(command.get(command.indexOf("--output") + 1)),
                    NativeLibraryValidatorTest.elf(62, true));
            return new ProcessExecutor.Result(0, false, "compiled");
        });
        final NativeCompilationResult result = compiler.compileExplicitLocalAot(module(NativeBackend.AOT),
                driver(), directory.resolve("output"), Set.of(HOST), HOST, "local-test", "1.0.0-alpha.1");
        assertEquals(2, calls.get());
        assertEquals(Set.of(HOST), result.libraries().keySet());
        assertTrue(Files.isRegularFile(result.libraries().get(HOST)));
        try (var files = Files.walk(directory.resolve("output"))) {
            assertTrue(files.noneMatch(file -> file.toString().contains(".skvm")));
        }
    }

    @Test void rejectsVmBeforeInvokingAnyProcess() throws Exception {
        final Path driver = driver();
        final NativeCompilationException failure = assertThrows(NativeCompilationException.class,
                () -> rejectingCompiler().compileExplicitLocalAot(module(NativeBackend.VM), driver,
                        directory.resolve("vm-output"), Set.of(HOST), HOST, "test", "1.0.0-alpha.1"));
        assertTrue(failure.getMessage().contains("AOT-only"));
        assertFalse(Files.exists(directory.resolve("vm-output")));
    }

    @Test void rejectsRelativeExecutableBeforeProcessInvocation() {
        assertThrows(NativeCompilationException.class, () -> rejectingCompiler().compileExplicitLocalAot(
                module(NativeBackend.AOT), Path.of("skidllvm"), directory.resolve("output"),
                Set.of(HOST), HOST, "test", "1.0.0-alpha.1"));
    }

    @Test void rejectsCrossTargetAndEmptyTargetRequests() throws Exception {
        final Path driver = driver();
        for (Set<NativeTarget> targets : List.of(Set.<NativeTarget>of(), Set.of(NativeTarget.WINDOWS_X86_64))) {
            assertThrows(NativeCompilationException.class, () -> rejectingCompiler().compileExplicitLocalAot(
                    module(NativeBackend.AOT), driver, directory.resolve("output"), targets,
                    HOST, "test", "1.0.0-alpha.1"));
        }
    }

    @Test void rejectsWrongVersionWithoutCompiling() throws Exception {
        final AtomicInteger calls = new AtomicInteger();
        final ProcessNativeCompiler compiler = compiler((command, work, timeout) -> {
            calls.incrementAndGet();
            assertTrue(command.contains("--version"));
            return new ProcessExecutor.Result(0, false, "wrong version");
        });
        assertThrows(NativeCompilationException.class, () -> compiler.compileExplicitLocalAot(
                module(NativeBackend.AOT), driver(), directory.resolve("output"), Set.of(HOST),
                HOST, "test", "1.0.0-alpha.1"));
        assertEquals(1, calls.get());
    }

    @Test void rejectsPathTraversalBuildId() throws Exception {
        final Path driver = driver();
        assertThrows(IllegalArgumentException.class, () -> rejectingCompiler().compileExplicitLocalAot(
                module(NativeBackend.AOT), driver, directory.resolve("output"), Set.of(HOST),
                HOST, "../escape", "1.0.0-alpha.1"));
    }

    @Test void refusesSelectiveEntriesOnAnOlderCompiler() throws Exception {
        NativeModule module = new NativeModule("selective", 1, Map.of("registration", "class-local-v1"))
                .addFunction(new NativeFunction("copy", "example/Test", "copy", "()V", NativeType.Primitive.VOID,
                        List.of(), "entry", NativeBackend.AOT, false, Map.of("java.entry", "copy"))
                        .addBlock(new NativeBlock("entry").terminate(NativeTerminator.Return.voidReturn())));
        ProcessNativeCompiler compiler = compiler((command, work, timeout) -> {
            if (command.contains("--version")) return new ProcessExecutor.Result(0, false, VERSION);
            assertTrue(command.contains("--contract"), "must reject before compiling");
            return new ProcessExecutor.Result(0, false, "{\"capabilities\":[\"class-local-registration-v1\"]}");
        });
        var failure = assertThrows(NativeCompilationException.class, () -> compiler.compileExplicitLocalAot(module,
                driver(), directory.resolve("output"), Set.of(HOST), HOST, "test", "1.0.0-alpha.1"));
        assertTrue(failure.getMessage().contains("selective-java-entries-v1"));
    }

    private Path driver() throws Exception {
        final Path file = directory.resolve("skidllvm").toAbsolutePath();
        Files.write(file, new byte[]{1});
        return file;
    }

    private ProcessNativeCompiler rejectingCompiler() {
        return compiler((command, work, timeout) -> {
            throw new AssertionError("Invalid local build must not invoke a process");
        });
    }

    private ProcessNativeCompiler compiler(ProcessExecutor executor) {
        return new ProcessNativeCompiler(ignored -> "; fixture\n".getBytes(StandardCharsets.UTF_8),
                executor, Duration.ofSeconds(1), new NativeIrVerifier());
    }

    private NativeModule module(NativeBackend backend) {
        return new NativeModule("local-test").addFunction(new NativeFunction(
                "skid_noop", "example/Test", "noop", "()V", NativeType.Primitive.VOID,
                List.of(), "entry", backend, false, Map.of())
                .addBlock(new NativeBlock("entry").terminate(NativeTerminator.Return.voidReturn())));
    }
}
