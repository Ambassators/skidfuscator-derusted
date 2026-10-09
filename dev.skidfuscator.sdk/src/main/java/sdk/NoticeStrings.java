package sdk;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/** Final runtime XOR for notice-backed strings. Notice literals live at their call sites. */
public final class NoticeStrings {
    private static final ConcurrentMap<String, byte[]> HASHES = new ConcurrentHashMap<>();

    private NoticeStrings() {}

    public static String finish(final String encoded, final String notice) {
        final byte[] bytes = Base64.getDecoder().decode(encoded);
        final byte[] hash = HASHES.computeIfAbsent(notice, NoticeStrings::hash);
        for (int i = 0; i < bytes.length; i++) bytes[i] ^= hash[i % hash.length];
        return new String(bytes, StandardCharsets.UTF_8);
    }

    private static byte[] hash(final String notice) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(notice.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 is unavailable", impossible);
        }
    }
}
