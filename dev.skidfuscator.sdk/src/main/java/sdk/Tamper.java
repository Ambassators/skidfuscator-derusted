package sdk;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Runtime self-integrity helper injected into obfuscated output.
 *
 * <p>Each protected class A contains, in its {@code <clinit>}, a call to
 * {@link #verify(Class, long)}, {@link #verifyExit(Class, long)} or
 * {@link #verifySilent(Class, long)} naming a <em>different</em> class B and B's
 * expected whole-file checksum. At runtime A reads B's on-disk {@code .class}
 * bytes, hashes them, and reacts if the hash no longer matches — so patching B
 * trips a checker that lives in A (a cross-class mesh).</p>
 *
 * <p>The three reactions trade visibility for immediacy: {@code verify} raises
 * an error and {@code verifyExit} halts the JVM <em>at the check site</em> (loud,
 * but the crash stack points straight at the check); {@code verifySilent} instead
 * lets the check return normally and arms a deferred, off-thread reaction, so the
 * failure surfaces later and elsewhere (see {@link #verifySilent}).</p>
 *
 * <p>The hash is {@link LongHashFunction#xx3()} over the entire class file, the
 * same primitive the rest of the SDK already relies on for build/runtime hash
 * agreement. Unreadable or missing resources fail closed. This legacy checksum reads
 * resource bytes, not live JVM bytecode; use the sealed-archive runtime guard
 * for strict release validation and JVM launch policy.</p>
 */
public final class Tamper {

    /**
     * Guards the silent mode's one-shot deferred reaction: the first detected
     * mismatch arms it, any later detection is absorbed. A clean program never
     * flips this, so it stays {@code false} and no reaction thread is ever
     * started — the build is behaviourally identical to an unprotected one.
     */
    private static final AtomicBoolean ARMED = new AtomicBoolean(false);
    private static volatile long POISON = 0L;

    private Tamper() {
    }

    /**
     * Hard-fail by throwing when {@code target}'s checksum does not match
     * {@code expected}. Thrown from a {@code <clinit>} this surfaces as an
     * {@link ExceptionInInitializerError}, poisoning the tampered program.
     */
    public static void verify(final Class<?> target, final long expected) {
        if (!matches(target, expected)) {
            throw new IllegalStateException();
        }
    }

    /**
     * Hard-fail by halting the JVM when {@code target}'s checksum does not match
     * {@code expected}. {@link Runtime#halt(int)} skips shutdown hooks so the
     * exit cannot be trivially intercepted.
     */
    public static void verifyExit(final Class<?> target, final long expected) {
        if (!matches(target, expected)) {
            Runtime.getRuntime().halt(0x5C);
        }
    }

    /**
     * Silent reaction: on mismatch do <em>not</em> fail at the check site.
     * Instead arm a single deferred reaction and return normally, so the program
     * runs on past this {@code <clinit>} and only degrades later — from an
     * unrelated background thread, after a randomised delay. The eventual failure
     * is displaced in both time and stack from the check and (in a mesh) from the
     * class that was actually patched, defeating the "patch a class, read the
     * crash, delete the named check" workflow that {@link #verify} and
     * {@link #verifyExit} expose.
     *
     * <p>A correctly-running program never reaches the reaction path (every check
     * matches and all protected resources are readable), so it behaves
     * exactly like an unprotected build.</p>
     */
    public static void verifySilent(final Class<?> target, final long expected) {
        if (!matches(target, expected)) {
            detonate(expected);
        }
    }

    /**
     * Runtime poison for downstream hardening. Clean programs keep returning zero.
     * A detected mismatch flips this word before the deferred reaction fires, so
     * consumers can silently corrupt derived keys instead of only throwing/exiting.
     */
    public static long poison() {
        return POISON;
    }

    /**
     * Arm the silent reaction once. Spawns a thread that waits a jittered delay
     * and then halts the JVM with an innocuous exit code. The delay is derived
     * from the call (no fixed timing signature to fingerprint); the thread is
     * non-daemon so the reaction still fires even if the main thread finishes
     * first, and {@link Runtime#halt(int)} skips shutdown hooks and mimics a
     * clean exit.
     */
    private static void detonate(final long seed) {
        poison(seed);
        if (!ARMED.compareAndSet(false, true)) {
            return; // a reaction is already pending; absorb further detections silently
        }
        // System.nanoTime is monotonic and always available; >>> 1 keeps the
        // modulus operand non-negative. Window: 5s .. 45s after detection.
        final long delayMillis = 5000L + (((System.nanoTime() ^ seed) >>> 1) % 40000L);
        final Thread reaper = new Thread(() -> {
            try {
                Thread.sleep(delayMillis);
            } catch (final InterruptedException ignored) {
                // fall through and halt anyway
            }
            Runtime.getRuntime().halt(0);
        });
        reaper.setDaemon(false);
        reaper.start();
    }

    private static void poison(final long seed) {
        long value = seed ^ 0x9E3779B97F4A7C15L;
        value ^= value >>> 33;
        value *= 0xff51afd7ed558ccdL;
        value ^= value >>> 33;
        value *= 0xc4ceb9fe1a85ec53L;
        value ^= value >>> 33;
        if (value == 0L) {
            value = 0xD6E8FEB86659FD93L;
        }
        POISON ^= value;
    }

    private static boolean matches(final Class<?> target, final long expected) {
        if (target == null) {
            return false;
        }

        // Absolute resource path from the binary name (e.g. "/a/b/C.class"), resolved
        // against the class loader root. This matches the jar entry exactly and is
        // package- and inner-class-safe, unlike a package-relative simple name.
        final String resource = "/" + target.getName().replace('.', '/') + ".class";

        InputStream in = null;
        try {
            in = target.getResourceAsStream(resource);
            if (in == null) {
                // Unreadable bytes are unverifiable, not proof of a clean class.
                return false;
            }
            final long actual = LongHashFunction.xx3().hashBytes(readFully(in));
            return actual == expected;
        } catch (final IOException | RuntimeException t) {
            return false;
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (final IOException ignored) {
                }
            }
        }
    }

    private static byte[] readFully(final InputStream in) throws IOException {
        final ByteArrayOutputStream out = new ByteArrayOutputStream(8192);
        final byte[] buffer = new byte[8192];
        int read;
        while ((read = in.read(buffer)) != -1) {
            if ((long) out.size() + read > 16L * 1024 * 1024) {
                throw new IOException("Protected class exceeds verification size limit");
            }
            out.write(buffer, 0, read);
        }
        return out.toByteArray();
    }
}
