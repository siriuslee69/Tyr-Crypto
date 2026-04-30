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
