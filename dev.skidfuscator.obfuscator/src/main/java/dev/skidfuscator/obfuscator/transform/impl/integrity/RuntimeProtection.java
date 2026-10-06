package dev.skidfuscator.obfuscator.transform.impl.integrity;

import dev.skidfuscator.obfuscator.Skidfuscator;
import org.mapleir.asm.ClassNode;
import sdk.integrity.JvmPolicy;
import sdk.integrity.RuntimeGuard;

import java.io.File;
import java.io.IOException;

/** Output-pipeline adapter. Framework-specific lifecycle integration belongs to the application. */
public final class RuntimeProtection {
    private RuntimeProtection() { }

    public static boolean enabled(Skidfuscator skid) {
        return skid.getConfig().getBoolean("runtimeProtection.enabled", false);
    }

    public static void validate(Skidfuscator skid) throws IOException {
        if (!enabled(skid) && !skid.getConfig().getBoolean("tamperProtection.enabled", false)) return;
        if (!skid.getConfig().getBoolean("sdk.enabled", true)) {
            throw new IOException("Protection requires sdk.enabled=true; refusing an unprotected output");
        }
        if (skid.getConfig().getBoolean("fileCrasher.enabled", false)) {
            throw new IOException("Protection is incompatible with fileCrasher.enabled");
        }
        if (enabled(skid)) {
            JvmPolicy.validate(skid.getConfig().getInt("runtimeProtection.policy", JvmPolicy.STRICT));
            RuntimeGuard.validateInterval(skid.getConfig().getInt("runtimeProtection.intervalMillis", 30000));
        }
    }

    public static byte[] instrument(Skidfuscator skid, ClassNode original, byte[] bytes) {
        if (!enabled(skid) || original.isVirtual() || original.getName().startsWith("sdk/")
                || skid.getExemptAnalysis().isExempt(original)) return bytes;
        return RuntimeProtectionInstrumenter.instrument(bytes,
                skid.getConfig().getBoolean("runtimeProtection.methodChecks", true));
    }

    public static void seal(Skidfuscator skid, File archive) throws IOException {
        if (!enabled(skid)) return;
        ArchiveSealer.seal(archive, archive,
                skid.getConfig().getInt("runtimeProtection.policy", JvmPolicy.STRICT),
                skid.getConfig().getInt("runtimeProtection.intervalMillis", 30000));
        Skidfuscator.LOGGER.post("\r[integrity] final release verified: " + ArchiveSealer.verify(archive)
                + " entries; standard JVM attach requires -XX:+DisableAttachMechanism under strict policy.\n");
    }
}
