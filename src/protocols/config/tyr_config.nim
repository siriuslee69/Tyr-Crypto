## ---------------------------------------------------------
## Tyr Config <- sanitized runtime config.toml parser
## ---------------------------------------------------------

import std/[os, strutils]

type
  TyrConfigError* = object of CatchableError

  TyrConfig* = object
    allowExperimentalAlgorithms*: bool
    autoBuildNativeBackends*: bool
    maxInputBytes*: int
    preferredBackend*: string

  TyrUserConfig* = object
    profileName*: string
    benchmarkDevice*: string

const
  defaultTyrConfigPath* = "config.toml"
  defaultTyrUserConfigPath* = "userconfig.toml"
  tyrDefaultMaxInputBytes* = 1_073_741_824
  tyrHardMaxInputBytes* = 2_147_483_647
  tyrConfigTextLimit* = 65_536

proc defaultTyrConfig*(): TyrConfig =
  ## Returns the built-in runtime configuration defaults.
  result.allowExperimentalAlgorithms = true
  result.autoBuildNativeBackends = false
  result.maxInputBytes = tyrDefaultMaxInputBytes
  result.preferredBackend = "auto"

proc defaultTyrUserConfig*(): TyrUserConfig =
  ## Returns the built-in local user configuration defaults.
  result.profileName = "local"
  result.benchmarkDevice = ""

var
  tyrRuntimeConfig*: TyrConfig = defaultTyrConfig()
  tyrRuntimeUserConfig*: TyrUserConfig = defaultTyrUserConfig()

proc raiseConfig(message: string) {.raises: [TyrConfigError].} =
  ## Raises a config parser error with a stable prefix.
  raise newException(TyrConfigError, "Tyr config error: " & message)

proc isAllowedConfigChar(c: char): bool =
  ## Checks characters accepted in small config identifiers.
  if c >= 'a' and c <= 'z':
    return true
  if c >= 'A' and c <= 'Z':
    return true
  if c >= '0' and c <= '9':
    return true
  result = c in {'_', '-', '.', ':', ' ', '@'}

proc normalizeKey(k: string): string =
  ## Normalizes snake-case and kebab-case TOML keys.
  result = k.strip().replace("-", "_").toLowerAscii()

proc stripInlineComment(s: string): string =
  ## Removes TOML-style comments outside double quoted strings.
  var
    inQuote: bool = false
    i: int = 0
    c: char = '\0'
  while i < s.len:
    c = s[i]
    if c == '"':
      inQuote = not inQuote
    if c == '#' and not inQuote:
      if i == 0:
        return ""
      return s.substr(0, i - 1).strip()
    i = i + 1
  result = s.strip()

proc unquoteValue(v: string): string =
  ## Removes one matching quote pair from a scalar value.
  var t: string = v.strip()
  if t.len >= 2:
    if t[0] == '"' and t[t.high] == '"':
      return t.substr(1, t.high - 1)
    if t[0] == '\'' and t[t.high] == '\'':
      return t.substr(1, t.high - 1)
  result = t

proc sanitizeConfigPath*(path: string): string =
  ## Sanitizes a config path before file IO.
  result = path.strip()
  if result.len == 0:
    raiseConfig("config path is empty")
  if result.contains("\0"):
    raiseConfig("config path contains a null byte")

proc sanitizeConfigString*(value, key: string, maxLen: int,
    allowEmpty: bool): string =
  ## Sanitizes a small scalar string loaded from config text.
  var
    i: int = 0
    v: string = unquoteValue(value)
  if v.len == 0 and not allowEmpty:
    raiseConfig(key & " cannot be empty")
  if v.len > maxLen:
    raiseConfig(key & " is too long")
  i = 0
  while i < v.len:
    if not isAllowedConfigChar(v[i]):
      raiseConfig(key & " contains an unsupported character")
    i = i + 1
  result = v

proc parseBoolValue(value, key: string): bool =
  ## Parses a sanitized boolean scalar.
  var v: string = unquoteValue(value).strip().toLowerAscii()
  case v
  of "true", "yes", "on", "1":
    result = true
  of "false", "no", "off", "0":
    result = false
  else:
    raiseConfig(key & " must be a boolean")

proc parseIntValue(value, key: string): int =
  ## Parses a non-negative integer scalar.
  var v: string = unquoteValue(value).replace("_", "")
  try:
    result = parseInt(v)
  except ValueError:
    raiseConfig(key & " must be an integer")
  if result < 0:
    raiseConfig(key & " cannot be negative")

proc normalizeBackend(value: string): string =
  ## Sanitizes and normalizes the preferred backend selector.
  var v: string = sanitizeConfigString(value, "preferred_backend", 32, false)
  v = v.toLowerAscii()
  case v
  of "auto", "tyr", "custom", "libsodium", "liboqs", "openssl":
    result = v
  else:
    raiseConfig("preferred_backend is unsupported")

proc sanitizeTyrConfig*(cfg: TyrConfig): TyrConfig =
  ## Validates config values built by callers or loaded from TOML text.
  result = cfg
  result.preferredBackend = normalizeBackend(cfg.preferredBackend)
  if result.maxInputBytes <= 0:
    raiseConfig("max_input_bytes must be positive")
  if result.maxInputBytes > tyrHardMaxInputBytes:
    raiseConfig("max_input_bytes exceeds the hard limit")

proc sanitizeTyrUserConfig*(cfg: TyrUserConfig): TyrUserConfig =
  ## Validates user config values built by callers or loaded from TOML text.
  result = cfg
  result.profileName = sanitizeConfigString(cfg.profileName, "profile_name", 64, false)
  result.benchmarkDevice = sanitizeConfigString(
    cfg.benchmarkDevice, "benchmark_device", 96, true)

proc parseSection(line: string): string =
  ## Parses a TOML section header.
  if line.len < 3:
    raiseConfig("empty section header")
  if line[0] != '[' or line[line.high] != ']':
    raiseConfig("invalid section header")
  result = line.substr(1, line.high - 1).strip().toLowerAscii()
  if result.len == 0:
    raiseConfig("empty section name")

proc splitKeyValue(line: string): tuple[key: string, value: string] =
  ## Splits a TOML key/value scalar line.
  var pos: int = line.find('=')
  if pos <= 0:
    raiseConfig("expected key = value")
  result.key = normalizeKey(line.substr(0, pos - 1))
  result.value = line.substr(pos + 1).strip()
  if result.key.len == 0:
    raiseConfig("empty config key")
  if result.value.len == 0:
    raiseConfig(result.key & " has no value")

proc applyTyrConfigPair(S: var TyrConfig, key, value: string) =
  ## Applies one parsed config key/value pair.
  case key
  of "allow_experimental_algorithms":
    S.allowExperimentalAlgorithms = parseBoolValue(value, key)
  of "auto_build_native_backends":
    S.autoBuildNativeBackends = parseBoolValue(value, key)
  of "max_input_bytes":
    S.maxInputBytes = parseIntValue(value, key)
  of "preferred_backend":
    S.preferredBackend = normalizeBackend(value)
  else:
    raiseConfig("unknown tyr config key: " & key)

proc applyTyrUserConfigPair(S: var TyrUserConfig, key, value: string) =
  ## Applies one parsed user config key/value pair.
  case key
  of "profile_name":
    S.profileName = sanitizeConfigString(value, key, 64, false)
  of "benchmark_device":
    S.benchmarkDevice = sanitizeConfigString(value, key, 96, true)
  else:
    raiseConfig("unknown user config key: " & key)

proc parseTyrConfigText*(text: string): TyrConfig =
  ## Parses config.toml text into a sanitized runtime config.
  var
    section: string = "tyr"
    line: string = ""
    pair: tuple[key: string, value: string]
  if text.len > tyrConfigTextLimit:
    raiseConfig("config text is too large")
  result = defaultTyrConfig()
  for rawLine in text.splitLines():
    line = stripInlineComment(rawLine)
    if line.len == 0:
      continue
    if line[0] == '[':
      section = parseSection(line)
      if section != "tyr":
        raiseConfig("unsupported config section: " & section)
      continue
    pair = splitKeyValue(line)
    applyTyrConfigPair(result, pair.key, pair.value)
  result = sanitizeTyrConfig(result)

proc parseTyrUserConfigText*(text: string): TyrUserConfig =
  ## Parses userconfig.toml text into a sanitized user config.
  var
    section: string = "user"
    line: string = ""
    pair: tuple[key: string, value: string]
  if text.len > tyrConfigTextLimit:
    raiseConfig("user config text is too large")
  result = defaultTyrUserConfig()
  for rawLine in text.splitLines():
    line = stripInlineComment(rawLine)
    if line.len == 0:
      continue
    if line[0] == '[':
      section = parseSection(line)
      if section != "user":
        raiseConfig("unsupported user config section: " & section)
      continue
    pair = splitKeyValue(line)
    applyTyrUserConfigPair(result, pair.key, pair.value)
  result = sanitizeTyrUserConfig(result)

proc applyTyrConfig*(cfg: TyrConfig): TyrConfig =
  ## Stores a sanitized runtime config in the library global.
  result = sanitizeTyrConfig(cfg)
  tyrRuntimeConfig = result

proc applyTyrUserConfig*(cfg: TyrUserConfig): TyrUserConfig =
  ## Stores a sanitized user config in the library global.
  result = sanitizeTyrUserConfig(cfg)
  tyrRuntimeUserConfig = result

proc loadTyrConfig*(path: string = defaultTyrConfigPath): TyrConfig =
  ## Loads config.toml, sanitizes it, and updates the global runtime config.
  var p: string = sanitizeConfigPath(path)
  result = applyTyrConfig(parseTyrConfigText(readFile(p)))

proc loadTyrUserConfig*(path: string = defaultTyrUserConfigPath): TyrUserConfig =
  ## Loads userconfig.toml, sanitizes it, and updates the global user config.
  var p: string = sanitizeConfigPath(path)
  result = applyTyrUserConfig(parseTyrUserConfigText(readFile(p)))

proc loadOptionalTyrConfig*(path: string = defaultTyrConfigPath): TyrConfig =
  ## Loads config.toml when present, otherwise applies defaults.
  var p: string = sanitizeConfigPath(path)
  if fileExists(p):
    return loadTyrConfig(p)
  result = applyTyrConfig(defaultTyrConfig())

proc loadOptionalTyrUserConfig*(
    path: string = defaultTyrUserConfigPath): TyrUserConfig =
  ## Loads userconfig.toml when present, otherwise applies defaults.
  var p: string = sanitizeConfigPath(path)
  if fileExists(p):
    return loadTyrUserConfig(p)
  result = applyTyrUserConfig(defaultTyrUserConfig())
