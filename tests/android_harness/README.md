# Tyr Android Harness

This is a minimal Android host that executes the native Tyr custom-crypto test
binary packaged under `jniLibs`.

Behavior:
- launch app;
- app runs `libtyrtests.so` from `nativeLibraryDir`;
- stdout/stderr is captured;
- the output is shown in the activity and written to
  `files/last_test_output.txt`.

This harness exists to validate ARM64/NEON and emulator-hosted native test
executables without wiring a full JNI surface for the whole Tyr API.

The `asymmetric_full` target includes every pure-Nim asymmetric family plus the
strict certificate codec suite. Real Ed25519 PKCS#8 and X.509 fixture bytes are
embedded at compile time. NTRU and SABER response-file KATs remain host-only;
the device bundle runs their deterministic roundtrip and implicit-rejection
regressions.
