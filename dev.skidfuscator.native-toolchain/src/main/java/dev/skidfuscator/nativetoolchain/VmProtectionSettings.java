package dev.skidfuscator.nativetoolchain;

import java.util.Objects;

/**
 * Complete non-destructive native VM hardening policy passed to SkidVirtualizePass.
 * The policy is embedded in the authenticated VM payload and repeated on the
 * driver command line so a toolchain cannot silently compile a weaker profile.
 */
public record VmProtectionSettings(
        Profile profile,
        Response response,
        boolean integrity,
        boolean antiDebug,
        boolean antiInstrumentation,
        boolean timingChecks,
        boolean diversifiedDispatch,
        int handlerCloneCount,
        int superinstructionBudget,
        int decodedBlockCacheEntries,
        int delayedHaltMinimumMillis
) {
    public VmProtectionSettings {
        Objects.requireNonNull(profile, "profile");
        Objects.requireNonNull(response, "response");
        if (handlerCloneCount < 2 || handlerCloneCount > 32) {
            throw new IllegalArgumentException("handlerCloneCount must be in 2..32");
        }
        if (superinstructionBudget < 0 || superinstructionBudget > 256) {
            throw new IllegalArgumentException("superinstructionBudget must be in 0..256");
        }
        if (decodedBlockCacheEntries < 0 || decodedBlockCacheEntries > 4096) {
            throw new IllegalArgumentException("decodedBlockCacheEntries must be in 0..4096");
        }
        if (delayedHaltMinimumMillis < 0 || delayedHaltMinimumMillis > 86_400_000) {
            throw new IllegalArgumentException("delayedHaltMinimumMillis must be in 0..86400000");
        }
        if (response == Response.DELAYED_HALT && delayedHaltMinimumMillis == 0) {
            throw new IllegalArgumentException("DELAYED_HALT requires a positive halt delay");
        }
        if (response != Response.DELAYED_HALT && delayedHaltMinimumMillis != 0) {
            throw new IllegalArgumentException("A halt delay is valid only for DELAYED_HALT");
        }
    }

    public static VmProtectionSettings aggressive() {
        return new VmProtectionSettings(Profile.AGGRESSIVE, Response.DELAYED_HALT,
                true, true, true, true, true, 4, 48, 64, 250);
    }

    public static VmProtectionSettings standard() {
        return new VmProtectionSettings(Profile.STANDARD, Response.THROW,
                true, false, false, false, true, 2, 16, 32, 0);
    }

    public enum Profile { STANDARD, AGGRESSIVE }

    /** The only reactions accepted by the native VM contract. */
    public enum Response { THROW, HALT, DELAYED_HALT }
}
