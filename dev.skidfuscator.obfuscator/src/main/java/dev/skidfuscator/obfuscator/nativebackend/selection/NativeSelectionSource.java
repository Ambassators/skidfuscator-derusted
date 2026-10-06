package dev.skidfuscator.obfuscator.nativebackend.selection;

/** Describes why a method was selected for native protection. */
public enum NativeSelectionSource {
    ANNOTATION_EXPLICIT,
    ANNOTATION_DEFAULT,
    RULE,
    INCLUDE,
    THREADED_KEY,
    JAVA_COPY
}
