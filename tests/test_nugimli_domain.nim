## ------------------------------------------------------------------
## NuGimli Domain Tests <- tagged independent cross-width derivation
## ------------------------------------------------------------------

import std/[strutils, unittest]
import ../src/protocols/custom_crypto/nugimli/types
import ../src/protocols/custom_crypto/nugimli/domain
import ../src/protocols/custom_crypto/nugimli/cascade
import ../src/protocols/custom_crypto/nugimli/reference

suite "nugimli domain derivation":
  test "key and state domains are deterministic and independent":
    var
      source: NuGimli512
      A, B: CascadeMaterial1024
      tag: CascadeDomainTag = cascadeDomainTag("test/session/handshake")
      i: int = 0
    i = 0
    while i < source.len:
      source[i] = uint32(i + 1) * 0x9e3779b9'u32
      i = i + 1
    A = deriveCascade1024(source, tag, [1'u8, 2'u8, 3'u8])
    B = deriveCascade1024(source, tag, [1'u8, 2'u8, 3'u8])
    check A == B
    check A.state != A.key

  test "tag context purpose and target width separate outputs":
    var
      source: NuGimli1024
      A, B: CascadeMaterial512
      C: CascadeMaterial1024
      D: CascadeMaterial2048
      i: int = 0
    i = 0
    while i < source.len:
      source[i] = uint32(i) xor 0xa5a5a5a5'u32
      i = i + 1
    A = deriveCascade512(source, cascadeDomainTag("route/A"), [9'u8])
    B = deriveCascade512(source, cascadeDomainTag("route/B"), [9'u8])
    C = deriveCascade1024(source, cascadeDomainTag("route/A"), [9'u8])
    D = deriveCascade2048(source, cascadeDomainTag("route/A"), [10'u8])
    check A.state != B.state
    check A.key != B.key
    check A.state[0] != C.state[0]
    check C.state[0] != D.state[0]

  test "all nine source and target width combinations are available":
    var
      S512: NuGimli512
      S1024: NuGimli1024
      S2048: NuGimli2048
      tag: CascadeDomainTag = cascadeDomainTag("matrix/all-widths")
    discard deriveCascade512(S512, tag)
    discard deriveCascade512(S1024, tag)
    discard deriveCascade512(S2048, tag)
    discard deriveCascade1024(S512, tag)
    discard deriveCascade1024(S1024, tag)
    discard deriveCascade1024(S2048, tag)
    discard deriveCascade2048(S512, tag)
    discard deriveCascade2048(S1024, tag)
    discard deriveCascade2048(S2048, tag)

  test "tagged derivation vectors remain stable":
    var
      source: NuGimli512
      tag: CascadeDomainTag = cascadeDomainTag("vector/v1")
      A: CascadeMaterial512 = deriveCascade512(source, tag, [0'u8, 1'u8])
      B: CascadeMaterial1024 = deriveCascade1024(source, tag, [0'u8, 1'u8])
      C: CascadeMaterial2048 = deriveCascade2048(source, tag, [0'u8, 1'u8])
    check A.state[0] == 643965524'u32
    check A.key[0] == 990261405'u32
    check A.state[^1] == 2837822014'u32
    check A.key[^1] == 2236494776'u32
    check B.state[0] == 2064734442'u32
    check B.key[0] == 3402105082'u32
    check B.state[^1] == 425816062'u32
    check B.key[^1] == 1591042756'u32
    check C.state[0] == 1401813876'u32
    check C.key[0] == 3817966587'u32
    check C.state[^1] == 2743802596'u32
    check C.key[^1] == 1974757365'u32

  test "derived material supports independent keyed encryption":
    var
      source: NuGimli512
      M: CascadeMaterial2048
      C, P: NuGimli2048
    source[0] = 0x12345678'u32
    M = deriveCascade2048(source, cascadeDomainTag("storage/chunk-v1"),
      [0x42'u8])
    C = cascadeEncrypt2048(M.state, M.key)
    P = cascadeDecrypt2048(C, M.key)
    check P == M.state
    clearCascadeMaterial(M)
    check M == default(CascadeMaterial2048)

  test "invalid tags and source dimensions fail closed":
    var
      tooLong: string = repeat('x', cascadeDomainMaxTagBytes + 1)
      source: array[63, byte]
      tag: CascadeDomainTag
    expect ValueError:
      discard cascadeDomainTag("")
    expect ValueError:
      discard cascadeDomainTag(tooLong)
    tag = cascadeDomainTag("valid")
    expect ValueError:
      discard deriveCascade512(source, nugimli512Bits, tag)
