# Runtime protection and release integrity

The shared Java 8 runtime is in `dev.skidfuscator.sdk/src/main/java/sdk/integrity`. Build-side code is in `dev.skidfuscator.obfuscator/.../transform/impl/integrity`. Forge lifecycle integration belongs to the sibling Orbit project. This is local integrity enforcement, not a guarantee that client memory cannot be inspected.

## Enable for an ordinary Java application

Rebuild the Skidfuscator distribution before using the new feature. Editing source does not update an existing CLI JAR. Merge this configuration into the application's existing profile:

```hocon
sdk.enabled = true
fileCrasher.enabled = false
runtimeProtection {
    enabled = true
    policy = 127
    intervalMillis = 30000
    methodChecks = true
}
```

The generic feature is opt-in. Orbit's own release pipeline enables sealing separately by default. Do not apply generic method instrumentation indiscriminately to Forge/Mixin infrastructure; use Orbit's framework adapter and existing exclusions.

Eligible, non-exempt, non-SDK concrete classes receive class-initializer bootstrap calls. Concrete methods other than constructors/class initializers receive health checkpoints when `methodChecks=true`. Interfaces and annotations are skipped. An all-exempt or interface-only application needs an explicit `RuntimeGuard.bootstrap(Anchor.class)` entry point and checkpoints.

Instrumentation precedes legacy mesh hashing. Final archive sealing follows serialization, remapping, mesh stamping and resource output. Output is staged and verified before replacing the destination. SDK-disabled/file-crasher combinations fail instead of silently shipping without requested protection. The independent legacy `tamperProtection` mesh requires at least two eligible classes; its unreadable-resource handling now fails closed. Keep its default `THROW` action for explicit failures.

## Launch contract

Strict releases require a supported HotSpot JVM and these launcher arguments:

```text
-XX:+DisableAttachMechanism
-XX:-HeapDumpOnOutOfMemoryError
```

The runtime queries effective HotSpot flags, so a later flag overriding attach-disable is rejected. Java 8 and Java 17 fixtures are tested. Unsupported VMs fail with an actionable error. Strict policy rejects JDWP configuration, Java/native startup agents, explicit remote JMX, unsafe verification/class-loading overrides, and automatic OOM heap dumps. It avoids substring false positives and does not reject inert `-Xdebug`.

Policy bits are embedded build-time choices: JDWP=1, Java agents=2, native agents=4, require attach disabled=8, deny remote JMX=16, deny automatic OOM dump=32, deny unsafe overrides=64. Strict is 127. Unknown bits fail validation. Reducing the mask weakens protection; there is no runtime `-D...skip` switch.

Startup agents can execute before application bootstrap. Detection refuses protected application startup but cannot undo prior agent actions. Automatic OOM-dump restrictions do not prevent programmatic dumping by code already executing in the JVM.

## Integrity format and monitoring

`META-INF/skid-integrity/v1.idx` contains a canonical sorted inventory of names, lengths and SHA-256 digests. `sdk/integrity/ReleaseSeal.class` pins the inventory digest, policy and interval through methods, not javac-inlined constants. Only those two exact entries are excluded to avoid a hash cycle. Other classes, resources, nested libraries and native-library resources are included.

Missing/added/changed entries, missing metadata, duplicate ZIP names, unsafe paths, malformed index records, oversized archives and multi-release SDK replacements fail verification. Limits: 100,000 entries, 16 MiB index, 128 MiB per expanded entry, and 1 GiB total expanded/physical data.

Checks read the physical JAR, not transformed class-loader resources. A raw whole-file fingerprint around initial verification also detects later changes that preserve modification time or would be hidden by Java 8 ZIP caches. Rechecks default to 30 seconds; allowed intervals are 1-300 seconds. Each pass reads the archive, so measure I/O/CPU on target hardware. Method and game-thread checkpoints do no disk I/O.

The first error is permanently latched and thrown at protected checkpoints. A terminated/interrupted monitor fails health checks. A monitor that is suspended or hung but still alive is not reliably detected. The new runtime does not kill other processes, change OS privileges, delete files, send telemetry or silently corrupt output. Existing legacy checksum reaction modes are separate.

## Sealer API

`ArchiveSealer` is Java-8-compatible with the runtime and ASM core/tree on its classpath. CLI operations:

```text
seal INPUT OUTPUT [POLICY=127] [INTERVAL_MS=30000]
verify JAR
development INPUT OUTPUT
```

Main class: `dev.skidfuscator.obfuscator.transform.impl.integrity.ArchiveSealer`.

Inputs must contain all runtime helpers. Sealing alone does not install an application bootstrap hook. `verify` is read-only and parses seal bytecode as data, never executing the audited JAR. Write operations stage output, verify it and replace atomically where supported. Never modify a protected archive while it is running.

Unsealed source directories are development-only. Development JARs require the explicit build-time development marker. Ordinary unsealed JARs fail, and extracting a sealed release does not enable development mode. Production verification always rejects development markers.

Embedded JAR signatures are incompatible with this exact-entry inventory. Adding signatures after sealing changes entries; resealing signed contents invalidates signatures. Existing outer `.SF`, `.RSA`, `.DSA` and `.EC` files are rejected rather than silently stripped. Use a detached signature over the final bytes, checked by an independently trusted launcher/distribution channel.

## Security boundary

An attacker who can replace the verifier and root, reseal the application, control pre-bootstrap class loading, or modify the JVM can bypass local checks. This is not publisher authentication or remote attestation. Archive checks do not authenticate arbitrary live JIT/native state. Normal JNI libraries remain usable. Standard attach restrictions do not prevent arbitrary OS process-memory access, native debuggers, kernel access, or privileged code. Keep secrets and authoritative access decisions server-side; use a separately trusted launcher to validate publisher signatures and the intended JVM/mod distribution.

## Regression build

The independent test build compiles the SDK, sealer and instrumenter without the complete Java 17 obfuscator/native build:

```powershell
$env:JAVA_HOME = "$env:USERPROFILE\.jdks\corretto-1.8.0_452"
$env:PATH = "$env:JAVA_HOME\bin;$env:PATH"
$env:JAVA8_HOME = $env:JAVA_HOME
$env:JAVA17_HOME = "$env:USERPROFILE\.jdks\corretto-17.0.18"
.\gradlew.bat -p scripts/runtime-protection test --no-daemon
```

It runs 27 tests, including forked JVMs with `-Xverify:all`, live archive modification, effective flag overrides, startup agents, stopped monitoring, explicit development artifacts, metadata attacks and legacy fail-closed handling. Reports are in `build/runtime-protection-tests/test-results/test` and `build/runtime-protection-tests/reports/tests/test`. This does not rebuild the complete CLI.

JVM option reference: Oracle Java SE 8 Windows `java` tool documentation, sections on `DisableAttachMechanism`, agents, verification and `HeapDumpOnOutOfMemoryError`.
