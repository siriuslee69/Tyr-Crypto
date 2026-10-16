## ---------------------------------------------------------------------
## | ML-KEM KAT <- FIPS 203 ML-KEM against the published known answers  |
## ---------------------------------------------------------------------
##
## Record 0 of each size, built as `kem_kat_support.nim` describes.
## ML-KEM draws its randomness from the record generator in this order:
##
##   64 bytes  d || z  (ONE draw)  -----> keypair
##   32 bytes  m                   -----> encapsulation
##
## One 64-byte draw is not the same as two 32-byte draws: the NIST
## generator updates itself after every call. liboqs (mlkem-native) asks
## for 64 at once, so we do too. The list names are `ML-KEM-512/768/1024`;
## the same hashes are pinned in PQClean `crypto_kem/ml-kem-*/META.yml`.

import std/unittest

import runePragmas
import ./kem_kat_support
import ../../src/tyr/kems/mlkem as custom_mlkem

proc mlkemKatTranscript(v: custom_mlkem.MlKemVariant): string {.role: {orchestrator}.} =
  ## v: which ML-KEM size. Returns record 0 in the response-file layout.
  var
    seed48: seq[byte] = kemKatRootSeed()
    rec = default(PqNistDrbgState)
    dz: seq[byte] = @[]
    kp = default(custom_mlkem.MlKemTyrKeypair)
    env = default(custom_mlkem.MlKemTyrCipher)
  result.add("count = 0\n")
  appendKatField(result, "seed = ", seed48)
  rec = initNistDrbg(seed48)
  dz = nistDrbgRandomBytes(rec, 64)
  kp = custom_mlkem.mlkemTyrKeypairDerand(v, dz)
  appendKatField(result, "pk = ", kp.publicKey)
  appendKatField(result, "sk = ", kp.secretKey)
  env = custom_mlkem.mlkemTyrEncaps(v, kp.publicKey, nistDrbgRandomBytes(rec, 32))
  appendKatField(result, "ct = ", env.ciphertext)
  appendKatField(result, "ss = ", env.sharedSecret)
  check custom_mlkem.mlkemTyrDecaps(v, kp.secretKey, env.ciphertext) == env.sharedSecret

suite "mlkem kat":
  # {.testKind: tkRegression, covers: "mlkemTyrKeypairFromParts, mlkemTyrEncaps, mlkemTyrDecaps".}
  test "ML-KEM-512 single KAT hash matches the published corpus":
    check kemKatTranscriptHash(mlkemKatTranscript(custom_mlkem.mlkem512)) ==
      kemKatExpectedHash("ML-KEM-512")

  # {.testKind: tkRegression, covers: "mlkemTyrKeypairFromParts, mlkemTyrEncaps, mlkemTyrDecaps".}
  test "ML-KEM-768 single KAT hash matches the published corpus":
    check kemKatTranscriptHash(mlkemKatTranscript(custom_mlkem.mlkem768)) ==
      kemKatExpectedHash("ML-KEM-768")

  # {.testKind: tkRegression, covers: "mlkemTyrKeypairFromParts, mlkemTyrEncaps, mlkemTyrDecaps".}
  test "ML-KEM-1024 single KAT hash matches the published corpus":
    check kemKatTranscriptHash(mlkemKatTranscript(custom_mlkem.mlkem1024)) ==
      kemKatExpectedHash("ML-KEM-1024")
