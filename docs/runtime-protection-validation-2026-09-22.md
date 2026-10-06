# Runtime protection validation - September 22, 2026

## Passed

- Shared SDK/sealer/instrumenter: 27 JUnit tests, no failures/errors. Protected fixtures ran with bytecode verification on Corretto Java 8u452 and Java 17.0.18.
- Orbit: Java 8 main-source compilation and standalone sealer/audit-tool compilation.
- Forge transformer snapshot: 5 JUnit tests, no failures/errors.
- Actual Forge adapter with LaunchWrapper in isolated JVMs: 18 smoke checks passed. Coverage includes normal startup, source mismatch, prohibited export, missing completion, late transformers, baseline reset, loader replacement, attach policy, development artifacts, and archive tampering.
- Packaged Orbit hooks verified. A test-only archive copy was sealed and audited: 18,123 indexed entries.
- Read-only Gradle audit passed on that copy and rejected a changed copy. A before/after SHA-256 comparison proved the rejected candidate was not rebuilt, resealed or otherwise rewritten.
- `runClient --dry-run` confirmed development preparation task wiring without starting Minecraft.
- Targeted Java 17 compilation of changed Skidfuscator output-pipeline classes, using existing compiled project/standalone dependencies and Lombok, passed.
- `git diff --check` passed for the edited existing protection-integration files.

## Not certified / blockers

The full Orbit `build -PmodrinthAutoDeploy=false` failed in the existing `VerifyConstructorStrings` audit during `obfuscateJar`, reporting `com/orbitclient/orbitclient/util/vape/VapeV4Detector$2`. This was before final renaming/sealing. The audit was not disabled. No fully gated release or live Minecraft session has been validated.

The complete Skidfuscator Gradle build launched on Java 17 failed before compilation with `Unable to establish loopback connection` / `SocketException: Invalid argument: connect`. The independent Java 8 regression build and targeted Java 17 compilation do not substitute for a complete clean CLI rebuild. Existing CLI JARs were not replaced with a newly certified distribution.

No release was deployed to an installed launcher profile. Original unrelated working-tree changes were preserved. Test copies under Orbit's `build/runtime-protection-smoke` are not release artifacts.

## Evidence

In Skidfuscator:
- `build/runtime-protection-tests.log`
- `build/runtime-protection-tests/test-results/test/`
- `build/runtime-protection-integration-compile/compile.log`
- `build/runtime-protection-compile.log` (full-build launcher failure)

In Orbit:
- `build/test-results/test/TEST-com.orbitclient.orbitloader.security.TransformerSnapshotTest.xml`
- `build/runtime-protection-smoke/results.json` and individual logs
- `build/runtime-protection-readonly-audit.log`
- `build/runtime-protection-negative-audit.log`
- `build/runtime-protection-dev-taskgraph.log`
- `build/runtime-protection-release-build.log`

Usage, launch flags, threat-model limits and configuration are documented in each project's `docs/runtime-protection.md`.
