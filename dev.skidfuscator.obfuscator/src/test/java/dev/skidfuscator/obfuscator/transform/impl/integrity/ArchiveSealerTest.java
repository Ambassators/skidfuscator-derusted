package dev.skidfuscator.obfuscator.transform.impl.integrity;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import sdk.integrity.ArchiveIntegrity;
import sdk.integrity.JvmPolicy;
import sdk.integrity.RuntimeGuard;

import javax.tools.ToolProvider;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;

import static org.junit.jupiter.api.Assertions.*;

class ArchiveSealerTest {
    @TempDir Path directory;
    private int sequence;
    private static final List<String> HARDENED = Arrays.asList(
            "-XX:+DisableAttachMechanism", "-XX:-HeapDumpOnOutOfMemoryError");

    @Test void sealedInstrumentedReleaseRunsWithVerificationOnJava17AndOptionalJava8() throws Exception {
        File jar = release(true);
        assertTrue(ArchiveSealer.verify(jar) >= 6);
        for (File java : javaExecutables()) {
            Result result = run(java, jar, HARDENED, "normal");
            assertEquals(0, result.exit, java + "\n" + result.output);
            assertTrue(result.output.contains("OK"), result.output);
            System.out.println("Verified protected fixture with " + java);
        }
    }

    @Test void missingAttachFlagAndLastFlagOverrideFailClosed() throws Exception {
        File jar = release(false);
        for (File java : javaExecutables()) {
            Result missing = run(java, jar, Collections.<String>emptyList(), "normal");
            assertNotEquals(0, missing.exit, missing.output);
            assertTrue(missing.output.contains("DisableAttachMechanism"), missing.output);
            Result overridden = run(java, jar, Arrays.asList("-XX:+DisableAttachMechanism",
                    "-XX:-DisableAttachMechanism"), "normal");
            assertNotEquals(0, overridden.exit, overridden.output);
            assertTrue(overridden.output.contains("DisableAttachMechanism"), overridden.output);
        }
    }

    @Test void automaticHeapDumpPolicyUsesEffectiveFlag() throws Exception {
        File jar = release(false);
        Result result = run(javaExecutables().get(0), jar,
                Arrays.asList("-XX:+DisableAttachMechanism", "-XX:+HeapDumpOnOutOfMemoryError"), "normal");
        assertNotEquals(0, result.exit, result.output);
        assertTrue(result.output.contains("HeapDumpOnOutOfMemoryError"), result.output);
    }

    @Test void startupAgentIsRejectedButCannotBePreventedFromRunningFirst() throws Exception {
        Path classes = compile("Agent", "public final class Agent { public static void premain(String x) {"
                + "System.out.println(\"AGENT_STARTED\");} }");
        File agent = directory.resolve("agent with spaces.jar").toFile();
        Manifest manifest = new Manifest();
        manifest.getMainAttributes().put(Attributes.Name.MANIFEST_VERSION, "1.0");
        manifest.getMainAttributes().putValue("Premain-Class", "Agent");
        try (JarOutputStream out = new JarOutputStream(Files.newOutputStream(agent.toPath()), manifest)) {
            put(out, "Agent.class", Files.readAllBytes(classes.resolve("Agent.class")));
        }
        List<String> options = new ArrayList<String>(HARDENED);
        options.add("-javaagent:" + agent.getAbsolutePath());
        Result result = run(javaExecutables().get(0), release(false), options, "normal");
        assertNotEquals(0, result.exit, result.output);
        assertTrue(result.output.contains("AGENT_STARTED"), result.output);
        assertTrue(result.output.contains("Java startup agents are not permitted"), result.output);
    }

    @Test void modificationPreservingMtimeAfterBootstrapIsDetected() throws Exception {
        File jar = release(false);
        Path log = directory.resolve("live-modification.log");
        Process child = start(javaExecutables().get(0), jar, HARDENED, "normal", log);
        try {
            awaitReady(child, log);
            FileTime timestamp = Files.getLastModifiedTime(jar.toPath());
            // Appended data keeps the ZIP readable but changes the raw archive fingerprint.
            Files.write(jar.toPath(), new byte[]{42}, StandardOpenOption.APPEND);
            Files.setLastModifiedTime(jar.toPath(), timestamp);
            Result result = finish(child, log);
            assertNotEquals(0, result.exit, result.output);
            assertTrue(result.output.contains("archive changed after initialization"), result.output);
        } finally { if (child.isAlive()) child.destroyForcibly(); }
    }

    @Test void stoppedMonitorLatchesFailureAtApplicationCheckpoint() throws Exception {
        Result result = run(javaExecutables().get(0), release(false), HARDENED, "stop");
        assertNotEquals(0, result.exit, result.output);
        assertTrue(result.output.contains("monitor interrupted") || result.output.contains("monitor is not running"), result.output);
    }

    @Test void modifiedClassesIndexAndNonCanonicalRootAreRejected() throws Exception {
        File original = release(false);
        for (String name : Arrays.asList("Fixture.class", ArchiveIntegrity.INDEX, ArchiveIntegrity.SEAL)) {
            Map<String, byte[]> map = contents(original);
            byte[] bytes = map.get(name);
            map.put(name, Arrays.copyOf(bytes, bytes.length + 1));
            File changed = jar(map);
            assertThrows(IOException.class, () -> ArchiveSealer.verify(changed), name);
        }
    }

    @Test void developmentArtifactIsExplicitAndNeverPassesReleaseAudit() throws Exception {
        File input = fixture(false);
        assertThrows(IOException.class, () -> ArchiveSealer.verify(input));
        Result unsealed = run(javaExecutables().get(0), input, HARDENED, "normal");
        assertNotEquals(0, unsealed.exit, unsealed.output);
        ArchiveSealer.development(input, input);
        assertThrows(IOException.class, () -> ArchiveSealer.verify(input));
        Result dev = run(javaExecutables().get(0), input, Collections.<String>emptyList(), "normal");
        assertEquals(0, dev.exit, dev.output);
        assertTrue(dev.output.contains("DEV"), dev.output);
        ArchiveSealer.seal(input, input, JvmPolicy.STRICT, 30000);
        assertTrue(ArchiveSealer.verify(input) > 0);
    }

    @Test void extractingSealedReleaseDoesNotTurnItIntoDevelopment() throws Exception {
        File sealed = release(false);
        Path extracted = directory.resolve("extracted");
        for (Map.Entry<String, byte[]> entry : contents(sealed).entrySet()) {
            Path target = extracted.resolve(entry.getKey());
            Files.createDirectories(target.getParent());
            Files.write(target, entry.getValue());
        }
        Result result = run(javaExecutables().get(0), extracted.toFile(), HARDENED, "normal");
        assertNotEquals(0, result.exit, result.output);
        assertTrue(result.output.contains("same release JAR"), result.output);
    }

    @Test void failedSealingPreservesLastOutputAndRejectsSignedInput() throws Exception {
        File output = directory.resolve("last-good.jar").toFile();
        byte[] prior = "KEEP LAST GOOD OUTPUT".getBytes(StandardCharsets.UTF_8);
        Files.write(output.toPath(), prior);
        Map<String, byte[]> map = contents(fixture(false));
        map.put("META-INF/SIGNER.SF", new byte[]{1});
        File signed = jar(map);
        assertThrows(IOException.class, () -> ArchiveSealer.seal(signed, output, 127, 30000));
        assertArrayEquals(prior, Files.readAllBytes(output.toPath()));
        map.remove("META-INF/SIGNER.SF");
        map.remove("sdk/integrity/RuntimeGuard.class");
        File incomplete = jar(map);
        assertThrows(IOException.class, () -> ArchiveSealer.seal(incomplete, output, 127, 30000));
        assertArrayEquals(prior, Files.readAllBytes(output.toPath()));
        assertThrows(IllegalArgumentException.class, () -> ArchiveSealer.seal(incomplete, output, 128, 30000));
        assertArrayEquals(prior, Files.readAllBytes(output.toPath()));
    }

    @Test void checkpointInstrumentationIsIdempotentAndCanBeStartupOnly() throws Exception {
        byte[] original = contents(fixture(false)).get("Fixture.class");
        byte[] once = RuntimeProtectionInstrumenter.instrument(original, true);
        assertArrayEquals(once, RuntimeProtectionInstrumenter.instrument(once, true));
        assertFalse(Arrays.equals(original, once));
        assertFalse(Arrays.equals(once, RuntimeProtectionInstrumenter.instrument(original, false)));
        byte[] helper = contents(fixture(false)).get("sdk/integrity/RuntimeGuard.class");
        assertArrayEquals(helper, RuntimeProtectionInstrumenter.instrument(helper, true));
    }

    private File release(boolean instrument) throws Exception {
        File input = fixture(instrument);
        ArchiveSealer.seal(input, input, JvmPolicy.STRICT, 30000L);
        return input;
    }

    private File fixture(boolean instrument) throws Exception {
        String source = "public final class Fixture {"
                + "public static int value(boolean b) {if(b)return 7;return 13;}"
                + "public static void main(String[] args) throws Exception {"
                + "if(!sdk.integrity.RuntimeGuard.bootstrap(Fixture.class)){System.out.println(\"DEV\");return;}"
                + "if(args.length>0 && args[0].equals(\"stop\")){"
                + "for(Thread t:Thread.getAllStackTraces().keySet())if(t.getName().equals(\"skid-integrity\")){t.interrupt();t.join(5000);}"
                + "sdk.integrity.RuntimeGuard.assertHealthy();}"
                + "System.out.println(\"READY\");System.out.flush();System.in.read();"
                + "sdk.integrity.RuntimeGuard.verifyNow();sdk.integrity.RuntimeGuard.assertHealthy();"
                + "if(value(true)!=7 || value(false)!=13)throw new AssertionError();System.out.println(\"OK\");}}";
        Path classes = compile("Fixture", source);
        Map<String, byte[]> entries = new LinkedHashMap<String, byte[]>();
        byte[] app = Files.readAllBytes(classes.resolve("Fixture.class"));
        entries.put("Fixture.class", instrument ? RuntimeProtectionInstrumenter.instrument(app, true) : app);
        for (String name : Arrays.asList("ArchiveIntegrity", "JvmPolicy", "ReleaseSeal", "RuntimeGuard",
                "RuntimeGuard$1", "RuntimeGuard$State")) {
            String path = "sdk/integrity/" + name + ".class";
            try (InputStream in = RuntimeGuard.class.getResourceAsStream("/" + path)) {
                entries.put(path, ArchiveIntegrity.readBounded(in, 1024 * 1024));
            }
        }
        entries.put("data.txt", "protected resource".getBytes(StandardCharsets.UTF_8));
        return jar(entries);
    }

    private Path compile(String name, String source) throws Exception {
        Path path = directory.resolve("compile-" + (++sequence));
        Files.createDirectories(path);
        Path java = path.resolve(name + ".java");
        Files.write(java, source.getBytes(StandardCharsets.UTF_8));
        ByteArrayOutputStream errors = new ByteArrayOutputStream();
        assertNotNull(ToolProvider.getSystemJavaCompiler(), "These integration tests require a JDK");
        int code = ToolProvider.getSystemJavaCompiler().run(null, null, errors, "-proc:none", "-source", "8", "-target", "8",
                "-classpath", RuntimeGuard.codeSource(RuntimeGuard.class).getAbsolutePath(), "-d", path.toString(), java.toString());
        assertEquals(0, code, errors.toString("UTF-8"));
        return path;
    }

    private File jar(Map<String, byte[]> entries) throws IOException {
        File result = directory.resolve("fixture-" + (++sequence) + ".jar").toFile();
        try (JarOutputStream out = new JarOutputStream(Files.newOutputStream(result.toPath()))) {
            for (Map.Entry<String, byte[]> entry : entries.entrySet()) put(out, entry.getKey(), entry.getValue());
        }
        return result;
    }
    private static void put(JarOutputStream out, String name, byte[] value) throws IOException {
        out.putNextEntry(new JarEntry(name)); out.write(value); out.closeEntry();
    }
    private static Map<String, byte[]> contents(File file) throws IOException {
        Map<String, byte[]> result = new LinkedHashMap<String, byte[]>();
        try (JarFile jar = new JarFile(file)) {
            Enumeration<JarEntry> entries = jar.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                if (!entry.isDirectory()) try (InputStream in = jar.getInputStream(entry)) {
                    result.put(entry.getName(), ArchiveIntegrity.readBounded(in, 16 * 1024 * 1024));
                }
            }
        }
        return result;
    }
    private static List<File> javaExecutables() {
        String executable = File.separatorChar == '\\' ? "java.exe" : "java";
        List<File> result = new ArrayList<File>();
        result.add(new File(System.getProperty("java.home"), "bin/" + executable));
        String java17 = System.getenv("JAVA17_HOME");
        if (java17 != null && !java17.isEmpty()) {
            File candidate = new File(java17, "bin/" + executable);
            assertTrue(candidate.isFile(), "Invalid JAVA17_HOME: " + java17);
            if (!candidate.equals(result.get(0))) result.add(candidate);
        }
        String java8 = System.getenv("JAVA8_HOME");
        if (java8 != null && !java8.isEmpty()) {
            File candidate = new File(java8, "bin/" + executable);
            assertTrue(candidate.isFile(), "Invalid JAVA8_HOME: " + java8);
            if (!candidate.equals(result.get(0))) result.add(candidate);
        }
        return result;
    }
    private Process start(File java, File classpath, List<String> flags, String argument, Path log) throws IOException {
        List<String> command = new ArrayList<String>();
        command.add(java.getAbsolutePath()); command.add("-Xverify:all"); command.addAll(flags);
        command.add("-cp"); command.add(classpath.getAbsolutePath()); command.add("Fixture"); command.add(argument);
        return new ProcessBuilder(command).redirectErrorStream(true).redirectOutput(log.toFile()).start();
    }
    private Result run(File java, File classpath, List<String> flags, String argument) throws Exception {
        Path log = directory.resolve("process-" + (++sequence) + ".log");
        Process child = start(java, classpath, flags, argument, log);
        try { return finish(child, log); }
        finally { if (child.isAlive()) child.destroyForcibly(); }
    }
    private static void awaitReady(Process child, Path log) throws Exception {
        long end = System.nanoTime() + TimeUnit.SECONDS.toNanos(20);
        while (child.isAlive() && System.nanoTime() < end) {
            if (Files.exists(log) && new String(Files.readAllBytes(log), StandardCharsets.UTF_8).contains("READY")) return;
            Thread.sleep(20L);
        }
        fail("Fixture did not initialize: " + new String(Files.readAllBytes(log), StandardCharsets.UTF_8));
    }
    private static Result finish(Process child, Path log) throws Exception {
        try { child.getOutputStream().write('\n'); child.getOutputStream().close(); }
        catch (IOException alreadyExited) { /* inspect the actual exit/log below */ }
        assertTrue(child.waitFor(20, TimeUnit.SECONDS), "Fixture did not exit");
        return new Result(child.exitValue(), new String(Files.readAllBytes(log), StandardCharsets.UTF_8));
    }
    private static final class Result {
        final int exit; final String output;
        Result(int exit, String output) { this.exit = exit; this.output = output; }
    }
}
