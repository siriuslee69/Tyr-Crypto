## ---------------------------------------------------------
## Config Tests <- runtime config parser and sanitization
## ---------------------------------------------------------

import std/[os, unittest]

import ../src/protocols/config/tyr_config

suite "tyr config":
  test "config parser accepts defaults and explicit values":
    var cfg: TyrConfig = parseTyrConfigText("""
[tyr]
allow_experimental_algorithms = true
auto_build_native_backends = false
max_input_bytes = 4096
preferred_backend = "tyr"
""")
    check cfg.allowExperimentalAlgorithms
    check not cfg.autoBuildNativeBackends
    check cfg.maxInputBytes == 4096
    check cfg.preferredBackend == "tyr"

  test "user config parser accepts local preferences":
    var cfg: TyrUserConfig = parseTyrUserConfigText("""
[user]
profile_name = "bench-local"
benchmark_device = "ZY32M27XLK"
""")
    check cfg.profileName == "bench-local"
    check cfg.benchmarkDevice == "ZY32M27XLK"

  test "config parser rejects unsafe scalar characters":
    expect TyrConfigError:
      discard parseTyrConfigText("""
[tyr]
preferred_backend = "../openssl"
""")

  test "config parser rejects unknown keys":
    expect TyrConfigError:
      discard parseTyrConfigText("""
[tyr]
silent_fallback = true
""")

  test "optional config load applies defaults when absent":
    var
      root: string = joinPath(getCurrentDir(), "build", "config_tests")
      missing: string = joinPath(root, "missing_config.toml")
      cfg: TyrConfig
    createDir(root)
    if fileExists(missing):
      removeFile(missing)
    cfg = loadOptionalTyrConfig(missing)
    check cfg.preferredBackend == "auto"
    check tyrRuntimeConfig.preferredBackend == "auto"
