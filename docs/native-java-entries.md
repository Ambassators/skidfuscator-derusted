# Java bodies, native copies, and private entry removal

The AOT pipeline can retain a Java implementation for Java callers while emitting
an additional native implementation for resolvable native callers. It can also
remove a private Java method declaration whose implementation is used only by
direct native calls. Both features are opt-in and require a SkidLLVM driver
advertising `selective-java-entries-v1`.

```hocon
native {
  enabled = true
  defaultMode = AOT
  include = ["class{^app/Cold.*$}"]
  exempt = ["class{^app/Hot.*$}"]
  javaCopies.include = ["class{^app/Hot.*$}"]
  javaCopies.exempt = ["class{^app/HotRuntimeBridge$}"]
  prunePrivate.include = ["class{^app/Cold.*$}"]
  prunePrivate.keep = ["method{^discoveredByFramework$}"]
  entryReportFile = "build/java-entries.tsv"
}
```

`native.exempt` still prevents replacement of a Java body. The separate
`javaCopies.include` permission allows a second AOT body for those methods.
Only methods transitively reachable through resolvable native calls are copied;
unused copies and copies disconnected by a failed lowering are dropped. Java
copies receive no JNI trampoline, native registration row, or loader binding in
their original class. They retain their Java body and Java access flags.

The native resolver supports exact static calls, same-owner private special
calls, and virtual calls closed by a final method or class. Constructors,
class initializers, synchronized methods, interface wrappers, unresolved
inheritance, and open virtual dispatch are not copied by this policy. Copying a
method does not make its object operations JNI-free or establish a speedup.

## Removal scope and runtime contracts

`prunePrivate.include` declares a reviewed implementation scope where unannotated
private methods are not an external reflection/JNI API. It defaults to empty.
Java reflection with computed names, enumeration by external frameworks, and
external native lookups cannot be proved absent from a call graph. Keep those
classes/methods using `prunePrivate.keep` or `compatibility.methods`. Do not enable
removal over an arbitrary library without reviewing its discovery contracts.

Inside the configured scope, the policy preserves a method if it is:

- Non-private, synchronized, a constructor, a class initializer, or a wrapper.
- Annotated, a serialization hook, or pinned by the runtime contract registry.
- Referenced by surviving Java bytecode, including exempt classes, Java copies,
  unsuccessful lowerings, wrapper templates, and generated linkage helpers.
- Referenced by a method handle, lambda bootstrap, or nested constant-dynamic
  handle, including handles originally inside converted methods.
- Named by a string literal anywhere in the final output classes.
- Called natively through unresolved dispatch or from another owner. Cross-owner
  static direct calls still require `GetStaticMethodID` for JVM initialization.

Deletion is planned after lowering succeeds. Failed lowerings keep both their
Java code and all declarations that code references. The LLVM pass independently
rejects a native call that would dispatch through Java to a removed declaration.
The commit transaction removes declarations from both the ASM and Maple method
lists after compilation succeeds and restores them on a later commit failure.

Removed declarations and copies are omitted from `RegisterNatives` tables and
JNI trampoline generation. Native implementation functions remain available to
direct calls and participate in the existing native optimization/hardening passes.
Deleting a declaration is not a claim that every occurrence of its name or
descriptor disappears from native diagnostics or other metadata.

## Audit and regression coverage

`native.reportFile` remains a lowering report, not a successful commit report.
`native.entryReportFile` is written after successful native compilation and
commit. It records `NATIVE_ENTRY`, `JAVA_COPY`, `NATIVE_ONLY`, or `WRAPPER`, plus
the original and final Java member identities. A subsequent output-writing
failure can still prevent publication, so validate the actual output JAR.

The Orbit build's coverage audit checks this report against the emitted
classfiles. Removed methods must be private original bodies; Java copies must
still have a Java `Code` attribute. Unexpected missing methods fail the audit.

Tests live in `NativeEntryPolicyTest`, `NativeMethodCommitTransactionTest`, and
`ProcessNativeCompilerLocalAotTest`. The Java 8 end-to-end fixture is
`scripts/native-audit/selective-entries-fixture`; run it through Orbit's
`tools/skid_native/test_selective_entries.py`. It checks native and Java calls,
recursion, instance methods, lazy class initialization, exceptions, null
receivers, reference identity, reflection, lambdas, annotations, synchronization,
failed lowering, registration omission, and rejection of an unsafe removal.
