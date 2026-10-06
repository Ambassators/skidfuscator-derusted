package dev.skidfuscator.obfuscator.nativebackend.selection;

import dev.skidfuscator.annotations.NativeObfuscation;
import dev.skidfuscator.config.nativeobfuscation.NativeConfig;
import dev.skidfuscator.config.nativeobfuscation.NativeMode;
import dev.skidfuscator.config.nativeobfuscation.NativeRule;
import org.mapleir.asm.MethodNode;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AnnotationNode;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/** Resolves annotation, rule, include, and exemption precedence for native methods. */
public final class NativeCandidateSelector {
    static final String ANNOTATION_DESCRIPTOR = Type.getDescriptor(NativeObfuscation.class);

    private final NativeConfig config;
    private final List<NativeMethodMatcher> exemptions;
    private final List<NativeMethodMatcher> includes;
    private final List<CompiledRule> rules;

    public NativeCandidateSelector(final NativeConfig config) {
        this.config = Objects.requireNonNull(config, "config");
        this.exemptions = compileMatchers(config.getExemptions());
        this.includes = compileMatchers(config.getIncludes());
        this.rules = new ArrayList<>();
        for (NativeRule rule : config.getRules()) {
            rules.add(new CompiledRule(NativeMethodMatcher.compile(rule.getMatch()), rule.getMode()));
        }
    }

    public Optional<NativeSelection> select(final MethodNode method) {
        Objects.requireNonNull(method, "method");
        if (!config.isEnabled()
                || (config.getThreadedKeyConfig().isEnabled() && config.getThreadedKeyConfig().isOnly())
                || matchesAny(exemptions, method)) {
            return Optional.empty();
        }

        final AnnotationMode annotation = findAnnotationMode(method);
        if (annotation.present && annotation.mode != NativeMode.DEFAULT) {
            return Optional.of(new NativeSelection(
                    method,
                    annotation.mode,
                    NativeSelectionSource.ANNOTATION_EXPLICIT,
                    true
            ));
        }

        CompiledRule lastRule = null;
        for (CompiledRule rule : rules) {
            if (rule.matcher.matches(method)) {
                lastRule = rule;
            }
        }
        if (lastRule != null) {
            return Optional.of(new NativeSelection(
                    method,
                    resolveDefault(lastRule.mode),
                    NativeSelectionSource.RULE,
                    annotation.present
            ));
        }

        if (annotation.present) {
            return Optional.of(new NativeSelection(
                    method,
                    resolveDefault(annotation.mode),
                    NativeSelectionSource.ANNOTATION_DEFAULT,
                    true
            ));
        }
        if (matchesAny(includes, method)) {
            return Optional.of(new NativeSelection(
                    method,
                    resolveDefault(NativeMode.DEFAULT),
                    NativeSelectionSource.INCLUDE,
                    false
            ));
        }
        return Optional.empty();
    }

    private NativeMode resolveDefault(final NativeMode mode) {
        final NativeMode resolved = mode == NativeMode.DEFAULT ? config.getDefaultMode() : mode;
        if (resolved == NativeMode.DEFAULT) {
            throw new IllegalArgumentException("native.defaultMode cannot be DEFAULT");
        }
        return resolved;
    }

    private static AnnotationMode findAnnotationMode(final MethodNode method) {
        AnnotationNode annotation = find(method.node.visibleAnnotations);
        if (annotation == null) {
            annotation = find(method.node.invisibleAnnotations);
        }
        if (annotation == null) {
            return AnnotationMode.absent();
        }

        NativeMode mode = NativeMode.DEFAULT;
        if (annotation.values != null) {
            for (int i = 0; i + 1 < annotation.values.size(); i += 2) {
                if (!"mode".equals(annotation.values.get(i))) {
                    continue;
                }
                final Object value = annotation.values.get(i + 1);
                if (!(value instanceof String[]) || ((String[]) value).length != 2) {
                    throw new IllegalArgumentException("Malformed @NativeObfuscation mode on " + method);
                }
                try {
                    mode = NativeMode.valueOf(((String[]) value)[1]);
                } catch (IllegalArgumentException ex) {
                    throw new IllegalArgumentException("Unknown @NativeObfuscation mode on " + method, ex);
                }
            }
        }
        return new AnnotationMode(true, mode);
    }

    private static AnnotationNode find(final List<AnnotationNode> annotations) {
        if (annotations == null) {
            return null;
        }
        for (AnnotationNode annotation : annotations) {
            if (ANNOTATION_DESCRIPTOR.equals(annotation.desc)) {
                return annotation;
            }
        }
        return null;
    }

    private static List<NativeMethodMatcher> compileMatchers(final List<String> expressions) {
        if (expressions == null || expressions.isEmpty()) {
            return Collections.emptyList();
        }
        final List<NativeMethodMatcher> matchers = new ArrayList<>(expressions.size());
        for (String expression : expressions) {
            matchers.add(NativeMethodMatcher.compile(expression));
        }
        return Collections.unmodifiableList(matchers);
    }

    private static boolean matchesAny(final List<NativeMethodMatcher> matchers, final MethodNode method) {
        for (NativeMethodMatcher matcher : matchers) {
            if (matcher.matches(method)) {
                return true;
            }
        }
        return false;
    }

    private record CompiledRule(NativeMethodMatcher matcher, NativeMode mode) {
    }

    private record AnnotationMode(boolean present, NativeMode mode) {
        private static AnnotationMode absent() {
            return new AnnotationMode(false, NativeMode.DEFAULT);
        }
    }
}
