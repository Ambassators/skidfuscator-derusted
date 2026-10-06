package dev.skidfuscator.config.nativeobfuscation;

import com.typesafe.config.Config;
import dev.skidfuscator.config.DefaultConfig;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.function.Predicate;
import java.util.stream.Collectors;

/**
 * Typed view of the native AOT and VM configuration tree.
 */
public final class NativeConfig extends DefaultConfig {
    private static final List<String> DEFAULT_TARGETS = Collections.unmodifiableList(Arrays.asList(
            "windows-x86_64",
            "windows-aarch64",
            "linux-x86_64",
            "linux-aarch64",
            "macos-x86_64",
            "macos-aarch64"
    ));

    private final NativeToolchainConfig toolchainConfig;
    private final NativeVmConfig vmConfig;
    private final NativeThreadedKeyConfig threadedKeyConfig;

    public NativeConfig(final Config config, final String path) {
        super(config, path);
        final String childPrefix = path.isEmpty() ? "" : path + ".";
        this.toolchainConfig = new NativeToolchainConfig(config, childPrefix + "toolchain");
        this.vmConfig = new NativeVmConfig(config, childPrefix + "vm");
        this.threadedKeyConfig = new NativeThreadedKeyConfig(config, childPrefix + "threadedKey");
    }

    public boolean isEnabled() {
        return getBoolean("enabled", false);
    }

    public NativeMode getDefaultMode() {
        final NativeMode mode = getEnum("defaultMode", NativeMode.AOT);
        if (mode == NativeMode.DEFAULT) {
            throw new IllegalArgumentException("native.defaultMode must be AOT or VM");
        }
        return mode;
    }

    public List<String> getIncludes() {
        return immutableCopy(getStringList("include", Collections.emptyList()));
    }

    /** Explicitly permits an AOT copy while retaining the original Java implementation. */
    public List<String> getJavaCopyIncludes() {
        return immutableCopy(getStringList("javaCopies.include", Collections.emptyList()));
    }

    public List<String> getJavaCopyExemptions() {
        return immutableCopy(getStringList("javaCopies.exempt", Collections.emptyList()));
    }

    /** Reviewed closed-world scope: private entries in this scope may be removed. */
    public List<String> getPrunePrivateIncludes() {
        return immutableCopy(getStringList("prunePrivate.include", Collections.emptyList()));
    }

    public List<String> getPrunePrivateKeeps() {
        return immutableCopy(getStringList("prunePrivate.keep", Collections.emptyList()));
    }

    /** Explicit closed-world review permits removal regardless of Java visibility. */
    public List<String> getPruneEntryIncludes() {
        return immutableCopy(getStringList("pruneEntries.include", Collections.emptyList()));
    }

    public List<String> getPruneEntryKeeps() {
        return immutableCopy(getStringList("pruneEntries.keep", Collections.emptyList()));
    }

    /** Opt-in reviewed field storage; include expressions match original class names. */
    public boolean isNativeFieldStorageEnabled() { return getBoolean("fields.enabled", false); }
    public List<String> getNativeFieldIncludes() {
        return immutableCopy(getStringList("fields.include", Collections.emptyList()));
    }
    public List<String> getNativeFieldKeeps() {
        return immutableCopy(getStringList("fields.keep", Collections.emptyList()));
    }

    @Override
    public List<String> getExemptions() {
        return immutableCopy(super.getExemptions());
    }

    /**
     * Returns selection rules in declaration order. Consumers must preserve
     * this order because the last matching rule has precedence.
     */
    public List<NativeRule> getRules() {
        return get("rules", Collections.emptyList(), configPath -> Collections.unmodifiableList(
                config.getConfigList(configPath).stream()
                        .map(rule -> new NativeRule(
                                rule.getString("match"),
                                rule.getEnum(NativeMode.class, "mode")
                        ))
                        .collect(Collectors.toList())
        ));
    }

    /**
     * Applies the configured last-match-wins rule precedence. The predicate is
     * invoked with each rule's matcher expression.
     */
    public Optional<NativeRule> findLastMatchingRule(final Predicate<String> matcher) {
        NativeRule match = null;
        for (final NativeRule rule : getRules()) {
            if (matcher.test(rule.getMatch())) {
                match = rule;
            }
        }
        return Optional.ofNullable(match);
    }

    public List<NativeTarget> getTargets() {
        final LinkedHashSet<NativeTarget> targets = getStringList("targets", DEFAULT_TARGETS).stream()
                .map(NativeTarget::fromConfigValue)
                .collect(Collectors.toCollection(LinkedHashSet::new));
        if (targets.isEmpty()) {
            throw new IllegalArgumentException("native.targets must contain at least one supported target");
        }
        return Collections.unmodifiableList(new ArrayList<>(targets));
    }

    public NativeArtifactMode getArtifactMode() {
        return getEnum("artifacts", NativeArtifactMode.BOTH);
    }

    public NativeToolchainConfig getToolchainConfig() {
        return toolchainConfig;
    }

    public NativeVmConfig getVmConfig() {
        return vmConfig;
    }

    public NativeThreadedKeyConfig getThreadedKeyConfig() {
        return threadedKeyConfig;
    }

    private static <T> List<T> immutableCopy(final List<T> values) {
        return Collections.unmodifiableList(new ArrayList<>(values));
    }
}
