package dev.skidfuscator.nativetoolchain;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class VmProtectionSettingsValidationTest {
    @Test
    void delayedHaltRequiresAPositiveDelayMatchingTheNativeParser() {
        assertThrows(IllegalArgumentException.class,
                () -> policy(VmProtectionSettings.Response.DELAYED_HALT, 2, 32, 0));
        assertDoesNotThrow(() -> policy(VmProtectionSettings.Response.DELAYED_HALT, 2, 32, 1));
        assertDoesNotThrow(() -> policy(VmProtectionSettings.Response.DELAYED_HALT, 2, 32, 86_400_000));
        assertThrows(IllegalArgumentException.class,
                () -> policy(VmProtectionSettings.Response.DELAYED_HALT, 2, 32, 86_400_001));
    }

    @Test
    void immediateResponsesCannotCarryADelay() {
        for (var response : new VmProtectionSettings.Response[]{
                VmProtectionSettings.Response.THROW, VmProtectionSettings.Response.HALT}) {
            assertDoesNotThrow(() -> policy(response, 2, 32, 0));
            assertThrows(IllegalArgumentException.class, () -> policy(response, 2, 32, 1));
        }
    }

    @Test
    void acceptsDisabledCacheAndRejectsOutOfContractBounds() {
        assertDoesNotThrow(() -> policy(VmProtectionSettings.Response.THROW, 2, 0, 0));
        assertDoesNotThrow(() -> policy(VmProtectionSettings.Response.THROW, 32, 4096, 0));
        assertThrows(IllegalArgumentException.class,
                () -> policy(VmProtectionSettings.Response.THROW, 1, 32, 0));
        assertThrows(IllegalArgumentException.class,
                () -> policy(VmProtectionSettings.Response.THROW, 33, 32, 0));
        assertThrows(IllegalArgumentException.class,
                () -> policy(VmProtectionSettings.Response.THROW, 2, -1, 0));
        assertThrows(IllegalArgumentException.class,
                () -> policy(VmProtectionSettings.Response.THROW, 2, 4097, 0));
    }

    private static VmProtectionSettings policy(VmProtectionSettings.Response response,
                                               int clones, int cacheEntries, int delay) {
        return new VmProtectionSettings(VmProtectionSettings.Profile.STANDARD, response,
                true, false, false, false, true, clones, 16, cacheEntries, delay);
    }
}
