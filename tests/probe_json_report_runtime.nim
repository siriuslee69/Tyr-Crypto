## ==========================================================
## | JSON Report Runtime Probe                              |
## | -> Minimal JsonNode build/write path for Android runs  |
## ==========================================================

import std/[json, os, strutils, times]

proc buildRow(deviceLabel, deviceKind, family, variant, implementation, backend, operation: string,
    loops, warmup, opsPerCall: int, elapsedNs: int64): JsonNode =
  result = %*{
    "kind": "summary",
    "device_label": deviceLabel,
    "device_kind": deviceKind,
    "family": family,
    "variant": variant,
    "implementation": implementation,
    "backend": backend,
    "operation": operation,
    "loops": loops,
    "warmup": warmup,
    "ops_per_call": opsPerCall,
    "total_ns": elapsedNs,
    "avg_ns_per_call": (if loops > 0: float(elapsedNs) / float(loops) else: 0.0),
    "avg_ns_per_op": (if loops > 0 and opsPerCall > 0: float(elapsedNs) / float(loops * opsPerCall) else: 0.0)
  }

when isMainModule:
  var
    rows = newJArray()
    root: JsonNode
    payload: string = ""
    outPath = getEnv("JSON_PROBE_OUT")

  rows.add(buildRow("probe", "phone", "x25519", "curve25519", "pass1", "scalar", "shared_secret", 2000, 24, 1, 1384371510))
  rows.add(buildRow("probe", "phone", "x25519", "curve25519", "pass2", "scalar", "shared_secret", 2000, 24, 1, 1466558645))
  rows.add(buildRow("probe", "phone", "x25519", "curve25519", "pass3", "scalar", "shared_secret", 2000, 24, 1, 1458962135))
  rows.add(buildRow("probe", "phone", "x25519", "curve25519", "pass4", "scalar", "shared_secret", 2000, 24, 1, 1301400937))
  rows.add(buildRow("probe", "phone", "x25519", "curve25519", "pass1", "neon2x", "shared_secret_batch", 1000, 16, 2, 1615959322))
  rows.add(buildRow("probe", "phone", "x25519", "curve25519", "pass2", "neon2x", "shared_secret_batch", 1000, 16, 2, 1398816197))
  rows.add(buildRow("probe", "phone", "x25519", "curve25519", "pass3", "neon2x", "shared_secret_batch", 1000, 16, 2, 1993889947))
  rows.add(buildRow("probe", "phone", "x25519", "curve25519", "pass4", "neon2x", "shared_secret_batch", 1000, 16, 2, 1343649114))

  root = %*{
    "metadata": {
      "generated_local": now().format("yyyy-MM-dd'T'HH:mm:sszzz"),
      "generated_utc": getTime().utc.format("yyyy-MM-dd'T'HH:mm:ss'Z'"),
      "device_label": "probe",
      "device_kind": "phone",
      "device_model": "probe_device",
      "device_os": "Android",
      "profile": "mobile",
      "loop_scale": 0.5,
      "phase": "summary",
      "compiled_backend": "native_neon"
    },
    "rows": rows
  }

  payload = pretty(root)
  if outPath.len > 0:
    createDir(parentDir(outPath))
    writeFile(outPath, payload)
  else:
    echo payload
