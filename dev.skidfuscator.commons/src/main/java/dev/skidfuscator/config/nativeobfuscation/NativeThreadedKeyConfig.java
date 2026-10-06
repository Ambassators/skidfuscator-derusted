package dev.skidfuscator.config.nativeobfuscation;

import com.typesafe.config.Config;
import dev.skidfuscator.config.DefaultConfig;

/** Native reconstruction of threaded flow seeds, independent of method-body selection. */
public final class NativeThreadedKeyConfig extends DefaultConfig {
    public NativeThreadedKeyConfig(final Config config, final String path) {
        super(config, path);
    }

    /** Explicit opt-in. The enclosing native pipeline must also be enabled. */
    public boolean isEnabled() {
        return getBoolean("enabled", false);
    }

    /** Suppress application-method native selection, including annotations and rules. */
    public boolean isOnly() {
        return getBoolean("only", false);
    }

    public NativeMode getMode() {
        final NativeMode mode = getEnum("mode", NativeMode.VM);
        if (mode == NativeMode.DEFAULT) {
            throw new IllegalArgumentException("native.threadedKey.mode must be AOT or VM");
        }
        return mode;
    }

    /** Reject configurations that would otherwise silently leave requested keys in Java. */
    public void validate(final boolean nativeEnabled) {
        if (isOnly() && !isEnabled()) {
            throw new IllegalArgumentException(
                    "native.threadedKey.only requires native.threadedKey.enabled = true");
        }
        if (isEnabled()) {
            if (!nativeEnabled) {
                throw new IllegalArgumentException(
                        "native.threadedKey.enabled requires native.enabled = true");
            }
            getMode();
        }
    }
}
