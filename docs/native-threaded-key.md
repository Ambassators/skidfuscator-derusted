# Native threaded-key-only protection

## Selective protection

Set the following in the normal Skidfuscator configuration:

```hocon
interprocedural.enabled = true
native {
  enabled = true
  threadedKey {
    enabled = true
    only = true
    mode = VM
  }
}
```

`profiles/native-threaded-key-only.conf` supplies a Windows x86-64 integration profile with authenticated VM payload protection and exception-based failure handling. Merge it with your application's normal configuration and an authenticated SkidLLVM toolchain configuration. It is not a standalone compiler distribution.

`only = true` suppresses application-method native selection, including explicit annotations, include matchers, and native rules. Only generated seed-reconstruction helpers enter the native compilation module. Application method bodies remain Java; the threaded call sites invoke the generated helpers. Native loader initialization is installed in helper companions, not indiscriminately in application owners.

This flag does **not** disable unrelated Java transformations, freeze names/descriptors, or promise a byte-for-byte unchanged input JAR. Interprocedural seed threading itself changes eligible internal call signatures and call sites. Other Java obfuscation remains controlled by the application's existing transformer configuration. The installation regression test verifies that the native commit step does not further rewrite the already-threaded application class.

## Modes and widths

`mode = VM` sends helper IR to the encrypted native VM. `mode = AOT` selects native AOT helpers instead. `DEFAULT` is rejected so the helper mode cannot be changed implicitly through application defaults. Set `only = false` to allow normal native selection alongside key helpers.

The existing `seed.wide` setting chooses 32-bit `(I)I` or 64-bit `(J)J` reconstruction. Helpers use width-correct modular arithmetic and remain dependent on the supplied threaded seed. Equal mappings within a method are deduplicated. Generated companion and helper identities are protected from subsequent renaming.

The Java helper placeholder contains only a throw, not a Java reconstruction implementation or reconstruction constants. Its body is removed and the method marked native only after successful native compilation and resource installation. This is obfuscation of computation, not a guarantee that a secret is unrecoverable by an attacker controlling the process.

## Failure behavior

The build rejects inconsistent settings (`only` without `enabled`, enabled key protection with native disabled, or an unresolved helper mode). It also rejects key protection when no eligible threaded seed sites were generated. Entry points, callbacks, constructors, excluded methods, and other unsupported threading cases may leave an input with no eligible sites; the build does not silently report that input as protected.

Missing or unauthenticated toolchains, compilation errors, and installation errors are fatal when key protection is requested. There is no silent Java-helper fallback. The transactional installer restores methods, existing class initializers, class lists, and resource lists after failure. Output publication happens only after the native preparation stage succeeds.

The separate Explicit Zig development compiler accepts only its literal-String AOT fixture subset. It is not a native-key or VM fallback and must not be presented as a signed SkidLLVM release.

## VM cache and policy

The runtime honors `VmProtectionSettings.decodedBlockCacheEntries()` using an invocation-local authenticated-plaintext block cache. Capacity is bounded by the requested entry count, the method's block count, and a 4 MiB retained-byte limit. A zero setting disables caching. Oversized blocks or cache allocation failure use uncached execution rather than limiting valid Java behavior. Execution still validates and decodes block instructions; this is not a persisted decoded-operation cache.

Cache entries are wiped on eviction, on invocation completion, and before a configured halt/delay response. Cache state is never shared between threads or nested invocations. This improves repeated-block execution at the cost of retaining authenticated plaintext until eviction or invocation completion; no performance ratio is claimed without benchmarks.

Unauthenticated payloads are reported as validation failures, never allowed to choose `HALT` or `DELAYED_HALT`. Ordinary Java exceptions retain their original exception behavior rather than triggering a protection response. A delayed-halt policy requires a positive delay in both Java configuration and the native parser.

## Verification and release status

See `NATIVE_AUDIT_2026-09-22.md` for the measured local results and exact remaining gates. Unit, native-probe, real-JVM JNI, and transaction tests exercise the implementation, but they are not proof of a complete signed production compiler, every platform/JVM combination, or an end-to-end signed key-only output JAR. The release gates in `native-protection.md` remain applicable.
