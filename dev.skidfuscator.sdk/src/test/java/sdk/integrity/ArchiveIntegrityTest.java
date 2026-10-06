package sdk.integrity;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;

import static org.junit.jupiter.api.Assertions.*;

class ArchiveIntegrityTest {
    @TempDir Path directory;
    private int sequence;

    @Test void cleanArchiveIncludesResourcesAndUnicodeNames() throws Exception {
        Map<String, byte[]> entries = entries();
        entries.put("assets/\u03c0.txt", bytes("resource"));
        byte[] index = ArchiveIntegrity.createIndex(jar(entries));
        entries.put(ArchiveIntegrity.INDEX, index);
        assertEquals(2, ArchiveIntegrity.verify(jar(entries), hash(index)));
    }

    @Test void changedDeletedAndAddedEntriesAreRejected() throws Exception {
        Map<String, byte[]> original = entries();
        byte[] index = ArchiveIntegrity.createIndex(jar(original));
        original.put(ArchiveIntegrity.INDEX, index);
        Map<String, byte[]> changed = new LinkedHashMap<String, byte[]>(original);
        changed.put("data.txt", bytes("changed"));
        assertThrows(IOException.class, () -> ArchiveIntegrity.verify(jar(changed), hash(index)));
        Map<String, byte[]> deleted = new LinkedHashMap<String, byte[]>(original);
        deleted.remove("data.txt");
        assertThrows(IOException.class, () -> ArchiveIntegrity.verify(jar(deleted), hash(index)));
        Map<String, byte[]> added = new LinkedHashMap<String, byte[]>(original);
        added.put("injected.class", bytes("unexpected"));
        assertThrows(IOException.class, () -> ArchiveIntegrity.verify(jar(added), hash(index)));
    }

    @Test void missingOrModifiedIndexAndRootAreRejected() throws Exception {
        Map<String, byte[]> original = entries();
        byte[] index = ArchiveIntegrity.createIndex(jar(original));
        assertThrows(IOException.class, () -> ArchiveIntegrity.verify(jar(original), hash(index)));
        original.put(ArchiveIntegrity.INDEX, bytes("tampered"));
        assertThrows(IOException.class, () -> ArchiveIntegrity.verify(jar(original), hash(index)));
        original.put(ArchiveIntegrity.INDEX, index);
        original.remove(ArchiveIntegrity.SEAL);
        assertThrows(IOException.class, () -> ArchiveIntegrity.verify(jar(original), hash(index)));
    }

    @Test void malformedCanonicalIndexIsRejectedEvenWithMatchingHash() throws Exception {
        String[] invalid = {"", "SKID-INTEGRITY-1\n", "SKID-INTEGRITY-1\n%%%\t0\t" + zeros() + "\n",
                "SKID-INTEGRITY-1\nZGF0YS50eHQ=\t-1\t" + zeros() + "\n",
                "SKID-INTEGRITY-1\nZGF0YS50eHQ=\t00\t" + zeros() + "\n",
                "SKID-INTEGRITY-1\nZGF0YS50eHQ=\t0\tNOT_A_HASH\n"};
        for (String text : invalid) {
            Map<String, byte[]> map = entries();
            byte[] index = bytes(text);
            map.put(ArchiveIntegrity.INDEX, index);
            File archive = jar(map);
            assertThrows(IOException.class, () -> ArchiveIntegrity.verify(archive, hash(index)), text);
        }
    }

    @Test void duplicateZipNamesAreRejected() throws Exception {
        Map<String, byte[]> map = entries();
        map.put("one.bin", bytes("one"));
        map.put("two.bin", bytes("two"));
        File archive = jar(map);
        byte[] raw = Files.readAllBytes(archive.toPath());
        byte[] from = bytes("two.bin"), to = bytes("one.bin");
        int replacements = 0;
        for (int i = 0; i <= raw.length - from.length; i++) {
            boolean match = true;
            for (int j = 0; j < from.length; j++) match &= raw[i + j] == from[j];
            if (match) { System.arraycopy(to, 0, raw, i, to.length); replacements++; }
        }
        assertEquals(2, replacements); // local header and central-directory name
        Files.write(archive.toPath(), raw);
        assertThrows(IOException.class, () -> ArchiveIntegrity.createIndex(archive));
    }

    @Test void unsafePathsAndVersionedRuntimeReplacementsAreRejected() throws Exception {
        String[] paths = {"../x", "a/../b", "/absolute", "a\\b", "a//b", "C:evil", "a/./b", "a\n.txt"};
        for (String path : paths) assertThrows(IOException.class, () -> ArchiveIntegrity.validateName(path), path);
        Map<String, byte[]> map = entries();
        map.put("META-INF/versions/9/sdk/integrity/RuntimeGuard.class", bytes("replacement"));
        assertThrows(IOException.class, () -> ArchiveIntegrity.createIndex(jar(map)));
    }

    @Test void readsAreBoundedAndMissingFilesNeverPass() {
        assertThrows(IOException.class, () -> ArchiveIntegrity.readBounded(new ByteArrayInputStream(new byte[11]), 10));
        assertThrows(IOException.class, () -> ArchiveIntegrity.readBounded(null, 10));
        assertThrows(IOException.class, () -> ArchiveIntegrity.verify(directory.resolve("absent.jar").toFile(), zeros()));
        assertThrows(IOException.class, () -> ArchiveIntegrity.verify(directory.toFile(), ""));
    }

    @Test void indexGenerationIsIndependentOfArchiveEntryOrder() throws Exception {
        Map<String, byte[]> a = entries();
        a.put("z.txt", bytes("z"));
        Map<String, byte[]> b = new LinkedHashMap<String, byte[]>();
        b.put("z.txt", bytes("z"));
        b.putAll(entries());
        assertArrayEquals(ArchiveIntegrity.createIndex(jar(a)), ArchiveIntegrity.createIndex(jar(b)));
    }

    private Map<String, byte[]> entries() {
        Map<String, byte[]> result = new LinkedHashMap<String, byte[]>();
        // Root bytecode shape is tested by ArchiveSealerTest; this tests the archive verifier only.
        result.put(ArchiveIntegrity.SEAL, new byte[]{1});
        result.put("data.txt", bytes("original"));
        return result;
    }
    private File jar(Map<String, byte[]> entries) throws IOException {
        Path path = directory.resolve("fixture-" + (++sequence) + ".jar");
        try (JarOutputStream out = new JarOutputStream(Files.newOutputStream(path))) {
            for (Map.Entry<String, byte[]> entry : entries.entrySet()) {
                out.putNextEntry(new JarEntry(entry.getKey()));
                out.write(entry.getValue());
                out.closeEntry();
            }
        }
        return path.toFile();
    }
    private static byte[] bytes(String text) { return text.getBytes(StandardCharsets.UTF_8); }
    private static String hash(byte[] bytes) { return ArchiveIntegrity.hex(ArchiveIntegrity.digest(bytes)); }
    private static String zeros() { return String.format("%064d", 0); }
}
