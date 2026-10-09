package dev.skidfuscator.obfuscator.transform.impl.string;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

/** Build-time preparation of plaintext notice literals for the final string decode. */
final class NoticeXorPad {
    private NoticeXorPad() {}

    static List<String> read(final Path file) {
        final byte[] bytes;
        try (InputStream stream = Files.newInputStream(file)) {
            bytes = stream.readNBytes(65537);
        } catch (IOException ignored) {
            throw new IllegalArgumentException("Cannot read stringEncryption.noticeXor.keyFile");
        }
        if (bytes.length > 65536) {
            throw new IllegalArgumentException("Notice XOR file exceeds 64 KiB");
        }
        for (byte value : bytes) {
            if (value == 0) throw new IllegalArgumentException("Notice XOR file contains NUL bytes");
        }
        final String text;
        try {
            text = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(bytes)).toString();
        } catch (CharacterCodingException ignored) {
            throw new IllegalArgumentException("Notice XOR file must be UTF-8");
        }
        final List<String> lines = new ArrayList<>();
        final String normalized = text.startsWith("\uFEFF") ? text.substring(1) : text;
        for (String row : normalized.split("\\R")) {
            final String line = row.strip();
            if (line.isEmpty() || line.startsWith("#")) continue;
            if (lines.size() == 256 || line.getBytes(StandardCharsets.UTF_8).length > 4096) {
                throw new IllegalArgumentException("Notice XOR file exceeds line limits");
            }
            lines.add(line);
        }
        if (lines.isEmpty()) throw new IllegalArgumentException("Notice XOR file has no notice lines");
        return Collections.unmodifiableList(lines);
    }

    static String stage(final String input, final String notice) {
        final byte[] bytes = input.getBytes(StandardCharsets.UTF_8);
        final byte[] hash;
        try {
            hash = MessageDigest.getInstance("SHA-256").digest(notice.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 is unavailable", impossible);
        }
        for (int i = 0; i < bytes.length; i++) bytes[i] ^= hash[i % hash.length];
        return Base64.getEncoder().encodeToString(bytes);
    }
}
