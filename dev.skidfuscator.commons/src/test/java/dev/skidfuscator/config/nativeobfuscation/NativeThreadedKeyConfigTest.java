package dev.skidfuscator.config.nativeobfuscation;

import com.typesafe.config.ConfigFactory;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class NativeThreadedKeyConfigTest {
    @Test
    void defaultsToDisabledWithVmAsTheExplicitOptInMode() {
        final var config = config("");
        assertFalse(config.getThreadedKeyConfig().isEnabled());
        assertFalse(config.getThreadedKeyConfig().isOnly());
        assertEquals(NativeMode.VM, config.getThreadedKeyConfig().getMode());
        assertDoesNotThrow(() -> config.getThreadedKeyConfig().validate(config.isEnabled()));
    }

    @Test
    void acceptsKeyOnlyModeWithoutAnyApplicationMethodIncludes() {
        final var config = config("native { enabled = true, threadedKey { enabled = true, only = true, mode = VM } }");
        assertTrue(config.getIncludes().isEmpty());
        assertTrue(config.getThreadedKeyConfig().isOnly());
        assertDoesNotThrow(() -> config.getThreadedKeyConfig().validate(config.isEnabled()));
    }

    @Test
    void rejectsContradictoryFlagsAndAmbiguousModes() {
        for (final String hocon : new String[]{
                "native.threadedKey.only = true",
                "native.threadedKey.enabled = true",
                "native { enabled = true, threadedKey { enabled = true, mode = DEFAULT } }"}) {
            final var config = config(hocon);
            assertThrows(IllegalArgumentException.class,
                    () -> config.getThreadedKeyConfig().validate(config.isEnabled()), hocon);
        }
    }

    @Test
    void rejectsUnknownModeWithTheConfigurationLibraryDiagnostic() {
        final var config = config("native { enabled = true, threadedKey { enabled = true, mode = INVALID } }");
        assertThrows(com.typesafe.config.ConfigException.BadValue.class,
                () -> config.getThreadedKeyConfig().validate(config.isEnabled()));
    }

    private NativeConfig config(String hocon) {
        return new NativeConfig(ConfigFactory.parseString(hocon), "native");
    }
}
