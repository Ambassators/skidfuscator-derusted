package sdk.integrity;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.JarURLConnection;
import java.security.CodeSource;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Opt-in release integrity and JVM policy. No process killing, hidden responses, network access,
 * OS privilege changes, or writable system-property bypasses. Call assertHealthy at application
 * checkpoints; the monitor records failures, and those checkpoints refuse further protected work.
 */
public final class RuntimeGuard {
    private static final AtomicReference<SecurityException> FAILURE = new AtomicReference<SecurityException>();
    private static volatile State state;

    private RuntimeGuard() { }

    /** @return true for a guarded release, false only for an explicitly built development artifact. */
    public static synchronized boolean bootstrap(Class<?> anchor) {
        throwIfFailed();
        try {
            File archive = codeSource(anchor);
            File runtime = codeSource(RuntimeGuard.class);
            File sealSource = codeSource(ReleaseSeal.class);
            String indexHash = ReleaseSeal.indexHash();
            if (indexHash.isEmpty() && state == null) {
                // Extracting a sealed release does not qualify: its root remains nonempty.
                boolean exploded = archive.isDirectory() && runtime.isDirectory() && sealSource.isDirectory();
                boolean explicitDevJar = ReleaseSeal.development() && archive.isFile()
                        && archive.equals(runtime) && archive.equals(sealSource);
                if (exploded || explicitDevJar) return false;
            }
            if (!archive.isFile() || !archive.equals(runtime) || !archive.equals(sealSource)) {
                throw new SecurityException("[integrity] Protected classes must originate from the same release JAR");
            }
            if (state != null) {
                if (!archive.equals(state.archive)) throw new SecurityException("[integrity] Release source changed");
                assertHealthy();
                return true;
            }
            int policy = ReleaseSeal.policy();
            long interval = ReleaseSeal.intervalMillis();
            validateInterval(interval);
            JvmPolicy.enforce(policy);
            byte[] fingerprint = physicalHash(archive);
            ArchiveIntegrity.verify(archive, indexHash);
            if (!MessageDigest.isEqual(fingerprint, physicalHash(archive))) {
                throw new SecurityException("[integrity] Release changed during initial verification");
            }
            final State created = new State(archive, indexHash, fingerprint, policy, interval);
            Thread monitor = new Thread(new Runnable() {
                @Override public void run() {
                    try {
                        while (FAILURE.get() == null) {
                            Thread.sleep(created.interval);
                            verifyNow();
                        }
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        recordFailure("Integrity monitor interrupted", e);
                    } catch (Throwable e) {
                        recordFailure("Integrity monitor failed", e);
                        if (e instanceof VirtualMachineError) throw (VirtualMachineError) e;
                        if (e instanceof ThreadDeath) throw (ThreadDeath) e;
                    }
                }
            }, "skid-integrity");
            monitor.setDaemon(true);
            monitor.setContextClassLoader(null);
            created.monitor = monitor;
            state = created;
            monitor.start();
            return true;
        } catch (Exception | LinkageError e) {
            throw recordFailure("Release initialization failed", e);
        }
    }

    /** Constant-time, no file I/O; suitable for hot protected-method or game-thread checkpoints. */
    public static void assertHealthy() {
        throwIfFailed();
        State current = state;
        if (current == null) throw recordFailure("Release guard was not initialized", null);
        if (current.monitor == null || !current.monitor.isAlive()) {
            throw recordFailure("Integrity monitor is not running", null);
        }
    }

    /** Explicit synchronous verification, also used by the monitor and integration tests. */
    public static void verifyNow() {
        throwIfFailed();
        State current = state;
        if (current == null) throw recordFailure("Release guard was not initialized", null);
        try {
            JvmPolicy.enforce(current.policy);
            // A raw file stream avoids Java 8 ZipFile's native cache and detects changes to
            // the root class, ZIP metadata, timestamps, or a replacement preserving mtime.
            if (!MessageDigest.isEqual(current.fingerprint, physicalHash(current.archive))) {
                throw new SecurityException("[integrity] Release archive changed after initialization");
            }
            ArchiveIntegrity.verify(current.archive, current.indexHash);
        } catch (Exception | LinkageError e) {
            throw recordFailure("Release verification failed", e);
        }
    }

    /** Forge/application adapters use the same irreversible failure latch. */
    public static void reject(String reason) { throw recordFailure(reason, null); }

    public static File codeSource(Class<?> type) throws IOException {
        if (type == null) throw new IOException("[integrity] Missing anchor class");
        try {
            CodeSource source = type.getProtectionDomain().getCodeSource();
            URL location = source == null ? null : source.getLocation();
            // LaunchWrapper records the class-entry URL, unlike URLClassLoader's
            // archive URL. Unwrap only a local JAR; the same-archive and seal
            // comparisons in bootstrap still apply to the canonical file.
            if (location != null && "jar".equalsIgnoreCase(location.getProtocol())) {
                location = ((JarURLConnection) location.openConnection()).getJarFileURL();
            }
            if (location == null || !"file".equalsIgnoreCase(location.getProtocol())) {
                throw new IOException("[integrity] Unsupported or missing code source: " + type.getName());
            }
            return new File(location.toURI()).getCanonicalFile();
        } catch (java.net.URISyntaxException | SecurityException e) {
            throw new IOException("[integrity] Cannot resolve protected code source", e);
        }
    }

    public static void validateInterval(long millis) {
        if (millis < 1000L || millis > 300000L) {
            throw new IllegalArgumentException("Integrity interval must be between 1000 and 300000 milliseconds");
        }
    }

    private static byte[] physicalHash(File archive) throws IOException {
        final MessageDigest digest;
        try { digest = MessageDigest.getInstance("SHA-256"); }
        catch (NoSuchAlgorithmException e) { throw new IOException("SHA-256 unavailable", e); }
        long total = 0;
        try (InputStream in = new FileInputStream(archive)) {
            byte[] buffer = new byte[65536];
            int read;
            while ((read = in.read(buffer)) != -1) {
                total += read;
                if (total > ArchiveIntegrity.MAX_TOTAL_BYTES) throw new IOException("Release exceeds size limit");
                digest.update(buffer, 0, read);
            }
        }
        return digest.digest();
    }

    private static void throwIfFailed() {
        SecurityException failure = FAILURE.get();
        if (failure != null) throw failure;
    }

    private static SecurityException recordFailure(String reason, Throwable cause) {
        SecurityException failure = new SecurityException("[integrity] " + reason, cause);
        if (FAILURE.compareAndSet(null, failure)) {
            System.err.println(failure.getMessage() + (cause == null ? "" : ": " + cause.getMessage()));
        }
        return FAILURE.get();
    }

    private static final class State {
        final File archive;
        final String indexHash;
        final byte[] fingerprint;
        final int policy;
        final long interval;
        volatile Thread monitor;
        State(File archive, String indexHash, byte[] fingerprint, int policy, long interval) {
            this.archive = archive;
            this.indexHash = indexHash;
            this.fingerprint = fingerprint.clone();
            this.policy = policy;
            this.interval = interval;
        }
    }
}
