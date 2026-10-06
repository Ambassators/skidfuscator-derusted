package sdk.integrity;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

/** Physical archive verification, deliberately independent of transforming class loaders. */
public final class ArchiveIntegrity {
    public static final String INDEX = "META-INF/skid-integrity/v1.idx";
    public static final String SEAL = "sdk/integrity/ReleaseSeal.class";
    public static final int MAX_ENTRIES = 100000;
    public static final int MAX_INDEX_BYTES = 16 * 1024 * 1024;
    public static final long MAX_ENTRY_BYTES = 128L * 1024 * 1024;
    public static final long MAX_TOTAL_BYTES = 1024L * 1024 * 1024;
    private static final String HEADER = "SKID-INTEGRITY-1\n";

    private ArchiveIntegrity() { }

    /** Build-time inventory. Only the root class and its index are excluded to avoid a hash cycle. */
    public static byte[] createIndex(File archive) throws IOException {
        SortedMap<String, String> entries = scan(archive);
        StringBuilder index = new StringBuilder(HEADER);
        for (Map.Entry<String, String> entry : entries.entrySet()) {
            index.append(Base64.getEncoder().encodeToString(entry.getKey().getBytes(StandardCharsets.UTF_8)))
                    .append('\t').append(entry.getValue()).append('\n');
            if (index.length() > MAX_INDEX_BYTES) throw invalid("index exceeds limit");
        }
        return index.toString().getBytes(StandardCharsets.US_ASCII);
    }

    /** Reopens the file on every call; an unchanged timestamp is never treated as proof of integrity. */
    public static int verify(File archive, String expectedIndexHash) throws IOException {
        if (!isHash(expectedIndexHash)) throw invalid("missing or invalid release seal");
        final byte[] index;
        try (JarFile jar = new JarFile(requireArchive(archive), true)) {
            JarEntry entry = jar.getJarEntry(INDEX);
            JarEntry seal = jar.getJarEntry(SEAL);
            if (entry == null || entry.isDirectory() || seal == null || seal.isDirectory()
                    || seal.getSize() <= 0 || seal.getSize() > 65536) {
                throw invalid("release metadata missing");
            }
            try (InputStream in = jar.getInputStream(entry)) { index = readBounded(in, MAX_INDEX_BYTES); }
        }
        if (!MessageDigest.isEqual(unhex(expectedIndexHash), digest(index))) {
            throw invalid("integrity index changed");
        }
        SortedMap<String, String> expected = parseIndex(index);
        SortedMap<String, String> actual = scan(archive);
        if (!expected.keySet().equals(actual.keySet())) throw invalid("archive entry set changed");
        for (Map.Entry<String, String> entry : expected.entrySet()) {
            if (!entry.getValue().equals(actual.get(entry.getKey()))) {
                throw invalid("entry changed: " + entry.getKey());
            }
        }
        return expected.size();
    }

    private static SortedMap<String, String> parseIndex(byte[] bytes) throws IOException {
        String text = new String(bytes, StandardCharsets.US_ASCII);
        if (!text.startsWith(HEADER) || !text.endsWith("\n")) throw invalid("invalid index framing");
        SortedMap<String, String> result = new TreeMap<String, String>();
        String previous = null;
        String[] lines = text.substring(HEADER.length()).split("\n", -1);
        if (lines.length > MAX_ENTRIES + 1) throw invalid("too many index entries");
        for (int i = 0; i < lines.length - 1; i++) {
            String[] fields = lines[i].split("\t", -1);
            if (fields.length != 3 || !isHash(fields[2])) throw invalid("invalid index record");
            final byte[] nameBytes;
            try { nameBytes = Base64.getDecoder().decode(fields[0]); }
            catch (IllegalArgumentException e) { throw invalid("invalid entry name encoding"); }
            if (!Base64.getEncoder().encodeToString(nameBytes).equals(fields[0])) {
                throw invalid("non-canonical entry name encoding");
            }
            final String name;
            try {
                name = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                        .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(nameBytes)).toString();
            } catch (CharacterCodingException e) { throw invalid("invalid UTF-8 entry name"); }
            validateName(name);
            if (name.endsWith("/") || reserved(name) || (previous != null && previous.compareTo(name) >= 0)) {
                throw invalid("non-canonical index order");
            }
            final long size;
            try { size = Long.parseLong(fields[1]); }
            catch (NumberFormatException e) { throw invalid("invalid entry size"); }
            if (size < 0 || size > MAX_ENTRY_BYTES || !Long.toString(size).equals(fields[1])) {
                throw invalid("entry size exceeds limit");
            }
            result.put(name, fields[1] + "\t" + fields[2]);
            previous = name;
        }
        if (result.isEmpty()) throw invalid("empty integrity inventory");
        return result;
    }

    private static SortedMap<String, String> scan(File archive) throws IOException {
        SortedMap<String, String> entries = new TreeMap<String, String>();
        Set<String> seen = new HashSet<String>();
        long total = 0;
        try (JarFile jar = new JarFile(requireArchive(archive), true)) {
            Enumeration<JarEntry> enumeration = jar.entries();
            while (enumeration.hasMoreElements()) {
                JarEntry entry = enumeration.nextElement();
                String name = entry.getName();
                validateName(name);
                if (!seen.add(name)) throw invalid("duplicate ZIP entry: " + name);
                if (seen.size() > MAX_ENTRIES) throw invalid("too many ZIP entries");
                if (name.startsWith("META-INF/versions/") && name.contains("/sdk/integrity/")) {
                    throw invalid("versioned runtime replacement is not supported");
                }
                if (entry.isDirectory()) continue;
                if (reserved(name)) continue;
                if (entry.getSize() > MAX_ENTRY_BYTES) throw invalid("entry exceeds limit: " + name);
                MessageDigest hash = sha256();
                long length = 0;
                try (InputStream in = jar.getInputStream(entry)) {
                    byte[] buffer = new byte[32768];
                    int count;
                    while ((count = in.read(buffer)) != -1) {
                        length += count;
                        if (length > MAX_ENTRY_BYTES || total + length > MAX_TOTAL_BYTES) {
                            throw invalid("archive expanded size exceeds limit");
                        }
                        hash.update(buffer, 0, count);
                    }
                }
                if (entry.getSize() >= 0 && entry.getSize() != length) throw invalid("ZIP size mismatch");
                total += length;
                entries.put(name, length + "\t" + hex(hash.digest()));
            }
        }
        if (entries.isEmpty()) throw invalid("empty archive");
        return entries;
    }

    public static void validateName(String name) throws IOException {
        if (name == null || name.isEmpty() || name.length() > 4096 || name.startsWith("/")
                || name.indexOf('\\') >= 0 || name.indexOf(':') >= 0) throw invalid("unsafe ZIP entry name");
        for (int i = 0; i < name.length(); i++) {
            if (name.charAt(i) < 32 || name.charAt(i) == 127) throw invalid("control character in ZIP entry name");
        }
        String path = name.endsWith("/") ? name.substring(0, name.length() - 1) : name;
        for (String part : path.split("/", -1)) {
            if (part.isEmpty() || part.equals(".") || part.equals("..")) throw invalid("unsafe ZIP entry path");
        }
    }

    public static boolean reserved(String name) { return INDEX.equals(name) || SEAL.equals(name); }

    public static byte[] readBounded(InputStream in, int limit) throws IOException {
        if (in == null) throw invalid("unreadable resource");
        ByteArrayOutputStream out = new ByteArrayOutputStream(Math.min(8192, limit));
        byte[] buffer = new byte[8192];
        int count;
        while ((count = in.read(buffer)) != -1) {
            if ((long) out.size() + count > limit) throw invalid("resource exceeds limit");
            out.write(buffer, 0, count);
        }
        return out.toByteArray();
    }

    public static byte[] digest(byte[] bytes) { return sha256().digest(bytes); }

    public static String hex(byte[] bytes) {
        char[] chars = new char[bytes.length * 2];
        final char[] alphabet = "0123456789abcdef".toCharArray();
        for (int i = 0; i < bytes.length; i++) {
            chars[i * 2] = alphabet[(bytes[i] & 255) >>> 4];
            chars[i * 2 + 1] = alphabet[bytes[i] & 15];
        }
        return new String(chars);
    }

    private static boolean isHash(String text) { return text != null && text.matches("[0-9a-f]{64}"); }
    private static byte[] unhex(String text) {
        byte[] bytes = new byte[32];
        for (int i = 0; i < bytes.length; i++) bytes[i] = (byte) Integer.parseInt(text.substring(i * 2, i * 2 + 2), 16);
        return bytes;
    }
    private static MessageDigest sha256() {
        try { return MessageDigest.getInstance("SHA-256"); }
        catch (NoSuchAlgorithmException e) { throw new IllegalStateException("SHA-256 unavailable", e); }
    }
    private static File requireArchive(File archive) throws IOException {
        if (archive == null || !archive.isFile()) throw invalid("release archive unavailable");
        return archive;
    }
    private static IOException invalid(String message) { return new IOException("[integrity] " + message); }
}
