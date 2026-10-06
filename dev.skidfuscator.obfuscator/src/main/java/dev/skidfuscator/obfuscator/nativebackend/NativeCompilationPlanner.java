package dev.skidfuscator.obfuscator.nativebackend;

import dev.skidfuscator.config.nativeobfuscation.NativeConfig;
import dev.skidfuscator.obfuscator.nativebackend.selection.NativeCandidateSelector;
import dev.skidfuscator.obfuscator.nativebackend.selection.NativeSelection;
import org.mapleir.asm.MethodNode;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/** Applies selection precedence and its documented strict/warn behavior. */
public final class NativeCompilationPlanner {
    private final NativeCandidateSelector selector;
    private final NativeConfig config;

    public NativeCompilationPlanner(final NativeConfig config) {
        this.selector = new NativeCandidateSelector(Objects.requireNonNull(config, "config"));
        this.config = config;
    }

    public NativeCompilationPlan plan(final Collection<? extends MethodNode> methods) {
        Objects.requireNonNull(methods, "methods");
        final List<NativeCompilationPlan.Candidate> candidates = new ArrayList<>();
        final List<NativeCompilationPlan.Skipped> skipped = new ArrayList<>();
        final List<String> strictFailures = new ArrayList<>();

        for (MethodNode method : methods) {
            final Optional<NativeSelection> selection = selector.select(method);
            if (selection.isEmpty()) {
                continue;
            }

            final NativeEligibility.Result eligibility = NativeEligibility.check(method);
            if (eligibility.isSupported()) {
                candidates.add(new NativeCompilationPlan.Candidate(
                        selection.get(),
                        eligibility.conversion()
                ));
                continue;
            }

            if (selection.get().isStrict()) {
                strictFailures.add(displayName(method) + ": " + eligibility.reason());
            } else {
                skipped.add(new NativeCompilationPlan.Skipped(selection.get(), eligibility.reason()));
            }
        }

        if (!strictFailures.isEmpty()) {
            throw new NativeSelectionException(
                    "Explicit native selection is unsupported:\n - " + String.join("\n - ", strictFailures)
            );
        }
        NativeJavaCopyPlanner.reserve(config, methods, candidates);
        return new NativeCompilationPlan(candidates, skipped);
    }

    /**
     * Revalidates the exact methods reserved before structural transformations.
     * Selection is intentionally not repeated against newly generated methods:
     * those methods were not protected from signature changes, merging, or
     * outlining and therefore cannot safely become native candidates late.
     */
    public NativeCompilationPlan revalidate(
            final NativeCompilationPlan reservation,
            final Collection<? extends MethodNode> currentMethods
    ) {
        Objects.requireNonNull(reservation, "reservation");
        Objects.requireNonNull(currentMethods, "currentMethods");

        final Set<MethodNode> liveMethods = Collections.newSetFromMap(new IdentityHashMap<>());
        liveMethods.addAll(currentMethods);

        final List<NativeCompilationPlan.Candidate> candidates = new ArrayList<>();
        final List<NativeCompilationPlan.Skipped> skipped = new ArrayList<>(reservation.skipped());
        final List<String> strictFailures = new ArrayList<>();
        for (NativeCompilationPlan.Candidate reserved : reservation.candidates()) {
            final NativeSelection selection = reserved.selection();
            final MethodNode method = selection.getMethod();
            final NativeEligibility.Result eligibility;
            if (!liveMethods.contains(method)) {
                eligibility = new NativeEligibility.Result(
                        NativeEligibility.Conversion.UNSUPPORTED,
                        "reserved method was removed by a transformation"
                );
            } else {
                eligibility = NativeEligibility.check(method);
            }

            if (eligibility.isSupported()) {
                candidates.add(new NativeCompilationPlan.Candidate(selection, eligibility.conversion()));
            } else if (selection.isStrict()) {
                strictFailures.add(displayName(method) + ": " + eligibility.reason());
            } else {
                skipped.add(new NativeCompilationPlan.Skipped(selection, eligibility.reason()));
            }
        }

        if (!strictFailures.isEmpty()) {
            throw new NativeSelectionException(
                    "Explicit native selection became unsupported after transformation:\n - "
                            + String.join("\n - ", strictFailures)
            );
        }
        return new NativeCompilationPlan(candidates, skipped);
    }

    private static String displayName(final MethodNode method) {
        return method.owner.getName() + "#" + method.getName() + method.getDesc();
    }
}
