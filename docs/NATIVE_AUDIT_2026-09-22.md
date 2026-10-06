# Native protection audit and implementation status — 2026-09-22

## Result

The current native-focused Java test selection passes **168/168 tests**, with **zero failures, skips, or aborts**, including a second run under `-Xcheck:jni`. The rebuilt Windows native driver/runtime test targets pass **4/4 CTest checks**. These results do not establish a production-ready, fully signed SkidLLVM release or a completed line-by-line audit of every repository file.

Work was performed in `skidfuscator-java-obfuscator` on branch `methodsig-obf` and the sibling `SkidLLVM` checkout. Existing uncommitted native, threaded-key, and runtime changes were preserved. No commit or push was made. The threaded-key implementation and several semantic fixes were already present at the start of this resumed session; the additions below were made on top of them.

## Changes made during this session

| Area | Finding and change | Evidence |
| --- | --- | --- |
| Native VM cache | The payload cache-entry setting was parsed but unused. Added an invocation-local authenticated-plaintext block cache, bounded by configured entries, method blocks, and 4 MiB retained bytes. Zero capacity disables caching; oversized blocks and cache allocation failure use uncached execution. | `SkidLLVM/runtime/skid_vm_runtime.cpp`, `SkidLLVM/tests/vm_runtime_test.cpp`; native tests and JNI cache-policy tests pass. |
| Secret lifetime | Added explicit wiping on cache eviction, completion, and before halt/delay handling. Entries never persist across invocations or share storage across threads/nested calls. | RAII cache ownership plus explicit pre-response `clear()`; bounds/eviction/nesting/disabled-cache C++ tests. |
| Unauthenticated response policy | The runtime previously selected a hostile-runtime response before authenticating the policy. It now authenticates a block before honoring halt/delay metadata and reports unverified payload failures through the safe JNI exception wrapper. | Real-JVM corrupted-payload tests for both `HALT` and `DELAYED_HALT` pass without terminating the JVM. |
| Policy parity | Java accepted a zero-delay `DELAYED_HALT` policy rejected by the native parser. Java now rejects it immediately. The C++ handler-clone lower bound now matches Java's minimum of two. | `VmProtectionSettingsValidationTest`; JNI/native tests. |
| Zig development bridge | Enabling the previously aborted fixture exposed an undefined exception-dispatch symbol. Added the correct status helper, preserving pending Java exceptions. Limited accepted input to the implemented literal-String-return subset before compiler invocation. This is not a production toolchain fallback. | `ExplicitZigNativeCompilerTest` compiles and loads a real DLL, verifies String contents/interning and zero measured Java allocation after warmup; unsupported-body preflight test passes. |
| Key-only failure paths | Added tests proving that no eligible seed sites fail closed, and that a missing authenticated toolchain leaves application methods/resources untouched. | `NativePipelineTest`. |
| Key-only installation | Added a transaction test that serializes the already-threaded application class before and after native helper installation and checks exact byte equality. Only the helper becomes native; loader initialization resides in its companion. | `NativeThreadedKeyCommitTest`. |
| Audit reporting | Added a strict standalone JUnit runner. Skipped/aborted tests produce exit code 2 rather than a green audit. Failures/no tests produce exit code 1. | `scripts/native-audit/NativeVerificationRunner.java`; final strict run exits 0. |
| Usage | Added the selective VM profile and documented mode/width behavior, failure handling, and limitations. | `profiles/native-threaded-key-only.conf`, `docs/native-threaded-key.md`. |

The cache retains authenticated plaintext, not a predecoded operation graph. Cache hits still execute the decoder/validator. No benchmark improvement ratio is claimed.

## Existing implementation reviewed and exercised

The threaded-key registry directly creates typed native helper IR for 32-bit and 64-bit modular reconstruction, keeps mappings out of Java helper bodies, deduplicates per-method mappings, reserves generated identities, and seals the helper set. Key-only selection overrides annotations, includes, and rules for application method bodies. Helpers join the same native compilation and transactional installation path as normal native candidates.

The reviewed lifecycle reserves identities before transforms and commits native changes after CFG dumping. Serialization reads the current class node rather than stale original class bytes. The existing initializer snapshot/rollback change is exercised by tests. Native execution tests also exercise signed arithmetic/conversions, parallel PHI behavior, negative switches, object identity, Java exception propagation/catching, return-buffer width guards, ciphertext/header rejection, and real-JVM concurrent key helpers.

This review is not a claim that unrelated application bytecode remains identical through every Java transformation. The precise key-only boundary is documented in `native-threaded-key.md`.

## Verification performed

| Check | Result |
| --- | --- |
| Fresh `javac` build of the 447 sources listed in `javac-main.args` | Passed on JDK 17. This covers the commons, native IR, native toolchain, and obfuscator source selection; other dependency outputs come from the existing local classpath. |
| Fresh compilation of 38 native-focused Java test source files | Passed. |
| Native-focused JUnit selection | 168 found, 168 passed, 0 failed/skipped/aborted. |
| Repeat with strict runner and `-Xcheck:jni` | 168 passed; no matched JNI warning/fatal diagnostics. |
| Real JNI tests | Seven methods pass, including concurrency, object/throwable identity, ordinary exceptions, tampering, unauthenticated halt policies, and cache settings. |
| Explicit Zig AOT fixture | Enabled using the existing explicit Zig executable; passed after the linkage repair. |
| Rebuilt C++ runtime/probe/JNI/driver targets | Passed with the existing MSVC Release configuration; runtime test targets retain warnings-as-errors. |
| CTest | 4/4: release contract, driver contract, direct-process invocation, VM runtime semantics. |
| `git diff --check` | No whitespace errors; Git prints existing LF/CRLF conversion notices. |
| Gradle invocation | Blocked before compilation: `java.io.IOException: Unable to establish loopback connection`. The fallback results are not reported as a successful Gradle build. |
| Full LLVM pass configuration | Blocked: CMake cannot find LLVM 18.1.8 (`LLVMConfig.cmake` / `llvm-config.cmake`). |

The initial 158-pass/one-abort result was not treated as final. Strict diagnostics identified the absent `SKID_TEST_ZIG` setting; supplying the installed executable revealed and enabled repair of the actual linker failure.

## Scope and limits

The inventory contained 532 first-party `src/main` Java source files across the modules. The fresh main compilation covered the 447-file native-related selection, not every module or vendored dependency. Manual review concentrated on native configuration/selection, threaded-key construction and call insertion, reserve/dump/commit ordering, transactional rollback, loader/packaging boundaries, Java/C++ VM contracts, runtime ownership/exceptions, and the development compiler failure. Existing native-specific tests were recompiled and executed.

A complete line-by-line audit of all first-party code, all 200-plus Java test/fixture sources, the vendored Maple code, external dependencies, and LLVM itself was **not completed**. Pattern searches and passing tests are not substitutes for that audit. No full static-analysis, sanitizer, fuzzing, or cross-platform performance certification is claimed.

## Remaining release gates

1. Supply/build the pinned LLVM 18.1.8 development installation and compile/test the real SkidLLVM pass plugin. The successful local `build-driver` configuration has `SKIDLLVM_BUILD_PASSES=OFF` and is explicitly a developer build.
2. Provision the legitimate release public key and authenticated toolchain distribution. `toolchain-keys.properties` currently contains comments only. No private key was read or created, no trust check was disabled, and no unsigned developer binary was promoted to a trusted release.
3. Exercise the complete production compiler/registration/loader pipeline on an actual key-only input/output JAR and a normally selected native/VM application using that authenticated toolchain. The transaction and JNI fixture tests cover separate boundaries, not that full release path.
4. Complete the six-target OS/architecture and JVM acceptance matrix, production sole-export/tamper checks, nested/reentrant/GC/class-loader stress cases, LLVM self-host gates, and the stated AOT/VM performance budgets from `native-protection.md`.
5. Restore a working Gradle build environment and run the broader repository test suite. Finish and document the remaining all-code audit separately from this native-focused review.

## Evidence and reproduction

Logs and argument files are under `.codex-test/native-audit-20260922/`:

- `desktop-javac-main.log`, `javac-main.args`, `javac-tests.args`.
- `desktop-final-tests.log`, `desktop-verification.args`: final strict 168-test run.
- `desktop-native-rebuild.log`, `desktop-native-tests.log`: rebuilt C++ targets and 4/4 CTest.
- `desktop-gradle-verification.log`: loopback failure.
- `desktop-llvm-plugin-probe.log`: missing pinned LLVM development package.
- `backup/resume/`: original native runtime/test bytes saved before this session's edits.

For this workspace, the strict run used these explicit environment variables:

```powershell
$env:SKID_VM_TEST_LIBRARY = 'C:\Users\Ambassator\Documents\Foreground\SkidLLVM\build-driver\Release\skid-vm-jni-test.dll'
$env:SKID_VM_TEST_EXECUTABLE = 'C:\Users\Ambassator\Documents\Foreground\SkidLLVM\build-driver\Release\skid-vm-program-probe.exe'
$env:SKID_TEST_ZIG = 'C:\Users\Ambassator\AppData\Local\Microsoft\WinGet\Links\zig.exe'
& 'C:\Program Files\Java\jdk-17\bin\javac.exe' '@.codex-test/native-audit-20260922/javac-main.args'
& 'C:\Program Files\Java\jdk-17\bin\javac.exe' '@.codex-test/native-audit-20260922/javac-tests.args' scripts/native-audit/NativeVerificationRunner.java
& 'C:\Program Files\Java\jdk-17\bin\java.exe' -Xcheck:jni '@.codex-test/native-audit-20260922/desktop-verification.args'
```

The argument files contain this workspace's local classpath and are not portable release build files. Rebuild the native test binaries before reusing them after runtime edits. Neither the JNI harness DLL nor the VM probe is a production artifact.
