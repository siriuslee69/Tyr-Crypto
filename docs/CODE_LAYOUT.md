# Code Layout

## One rule

Every algorithm's code lives in a **folder**. Beside it sits a `.nim` file of
the same name holding nothing but the export surface.

```
kems/mceliece.nim      <- the surface: imports the folder, exports it, no logic
kems/mceliece/         <- the implementation: operations, pk_gen, benes, ...
```

`import tyr/kems/mceliece` therefore stays short no matter how many files
the implementation needs, and reading the surface tells you what the
algorithm offers without wading through the mathematics.

The same shape repeats one level up: `src/tyr.nim` over `src/tyr/`.

## Repo Map

```
Path                             Responsibility
src/
  tyr.nim                        Everything, one name per operation
  tyr/
    kems.nim  kems/              Key agreement
      kyber/ mceliece/ frodo/ bike/ ntru/ saber/ x25519/
    signatures.nim  signatures/  Proving authorship
      dilithium/ falcon/ sphincs/ ed25519/ ecdsa_p256/
    hashes.nim  hashes/          Fingerprints
      blake3/ sha3/ sha256/ sha512/
    macs.nim  macs/              Keyed fingerprints
      hmac/ poly1305/
    kdfs.nim  kdfs/              Key derivation
      argon2/ blake3_gimli_kdf/ kdf/
    ciphers.nim  ciphers/        Encryption
      aes/ chacha/ gimli/ nugimli/
    otp.nim  otp/                HOTP / TOTP codes
    aeads.nim  aeads/            Encrypt AND prove nobody changed it
      composite.nim              The five suites Tyr layers itself
      gcm.nim                    AES-256-GCM, the one standard primitive
    certs/                       X.509 handling (der, pem, oid, chain, rsa/)
    bindings/                    Optional native backends
                                 (libsodium, liboqs, OpenSSL, PQClean, nimcrypto)
    helpers/                     Shared plumbing
      material.nim               What every typed material surface shares
      tiers.nim                  Backend tier enums
      random.nim                 CSPRNG + cryptoRand
      errors.nim  secure_memory.nim  bigint.nim  otter_support.nim
      common/                    ct_compare.nim, pq_rng.nim
      wasm/                      Wasm/JS bridge (level0..level2)
bindings/js/                     Wasm loader and TypeScript declarations
tests/                           Unit, vector, parity, benchmark and harness tests
tools/                           Builders, bench drivers, report scripts
submodules/                      Pinned upstream source dependencies
docs/                            Documentation
  benchmarks/                    Curated benchmark JSON snapshots
  research/                      Paper indices and optimization notes
build/                           Generated build artifacts (ignored)
```

## The five files every module has

| File          | What it is                                              |
|---------------|---------------------------------------------------------|
| `<module>.nim`| Default tier. One name per operation, picked by overload |
| `types.nim`   | The family enum, key shapes, and the safety warnings     |
| `dynamic.nim` | Runtime tier. Choose the family from a value             |
| `single.nim`  | Build-flag tier. One family, for small devices           |
| `material.nim`| Typed material. Key sizes carried by the type            |

`aeads/` has no `single.nim` and no `material.nim`, on purpose. Its five
composite suites are configurations of one engine rather than separate
implementations, so a build flag would have nothing to leave out, and the
key count varies per suite so a fixed-size material type cannot describe
them. `aeads.nim` says so where a reader will look for it.

## Four ways to reach an algorithm

```
import tyr                     keypair(kyber768)          <- overload on the
                                                             variant's TYPE
import tyr/kems/mceliece       mcelieceTyrKeypair(...)    <- one family, by
                                                             its own long name
import tyr/kems/dynamic        keypairOf(anyKemValue)     <- choose from a
                                                             VALUE at runtime
import tyr/kems/single         keypairSingle(kfKyber)     <- choose with
  (-d:tyrKem=kyber)                                          -d:, for IoT
```

The names differ per tier (`keypair` / `keypairOf` / `keypairSingle` /
`kyberTyrKeypair`) so all four can be imported side by side and never
collide.

Choosing what gets compiled is a build-time decision by nature: Nim
resolves every `import` before any of your code exists, so no `case` or
`when` written inside a proc can un-import a family. `single.nim` reduces
that to one flag with a readable value, and works with no flag at all.

## The material surface

Beside the four tiers, each module offers material types that carry the
exact key and nonce sizes:

```nim
var m = xchacha20cipherM(key: k, nonce: n)   # wrong size = won't compile
var ct = encrypt(message, m)
```

The family tiers take `openArray[byte]` and check lengths while running.
The material types make a wrong length a compile error instead.

```
helpers/material.nim        AlgorithmKind, algorithmLayouts, AsymEnvelope
   ^                        (shared: imports nothing)
   |
   +-- hashes/material.nim      blake3HashM sha3HashM ...
   +-- macs/material.nim        blake3hmacM poly1305hmacM ...
   +-- ciphers/material.nim     xchacha20cipherM aesCtrcipherM ...
   +-- signatures/material.nim  ed25519SignM falcon0VerifyM ...
   +-- kems/material.nim        kyber0SendM mceliece0OpenM ...
```

`AlgorithmKind` stays one flat list because `algorithmLayouts` is indexed
by it. Splitting the list would split the table into five that no longer
line up.

## Dependency Flow

```
User code
   |
   v
src/tyr.nim  (or one module umbrella, or one algorithm surface)
   |
   +--> tyr/<module>.nim          default tier, overloads
   |       |
   |       +--> tyr/<module>/<family>.nim      export surface
   |       |        +--> tyr/<module>/<family>/   implementation
   |       |
   |       +--> tyr/<module>/material.nim
   |                +--> tyr/helpers/material.nim
   |
   +--> tyr/bindings/*            when enabled by -d:has*
```

Implementations depend on `helpers/`, never on a module umbrella. Nothing
in `src/` imports a test or a tool.

## Data Flow

```
raw bytes or typed crypto material
   |
   v
sanitize/validate (check sizes, reject invalid inputs)
   |
   v
typed crypto material (kyber0SendM, dilithium0SignM, ...)
   |
   v
operation: hash / encrypt / sign / encapsulate
   |
   v
typed output: bytes, tag, signature, KEM envelope
```

## Naming Rules

| Name shape        | Meaning                                          |
|-------------------|--------------------------------------------------|
| `*Tyr*`           | This repo's own pure-Nim implementation          |
| unsuffixed        | Optional native backend path                     |
| `*M`              | Typed material object                            |
| `*SendM/*OpenM`   | KEM sender / opening material                    |
| `*SignM/*VerifyM` | Signature material                               |
| `*Of`             | Runtime tier (`dynamic.nim`)                     |
| `*Single`         | Build-flag tier (`single.nim`)                   |
| `*Pass1-4`        | Competing X25519 arithmetic optimization pass    |
| `*b3` / `*gi`     | Variant deriving its key material with BLAKE3 /  |
|                   | Gimli instead of the standard route. Two-letter  |
|                   | source codes: `hc` `xc` `b3` `gi`                |

## Swappable key derivation

Two algorithms need a value derived by a *second* algorithm, and Tyr lets
you choose which:

```
  xchacha20Xor      subkey from HChaCha20     <- standard, the default
  xchacha20b3Xor    subkey from BLAKE3
  xchacha20giXor    subkey from Gimli

  poly1305xcTag     one-time key from XChaCha20 keystream  <- the default
  poly1305b3Tag     one-time key from BLAKE3
  poly1305giTag     one-time key from Gimli
```

The default is always the standard construction, byte-identical to what
it was before the variants existed — `test_derive_sources.nim` asserts
that. The variants are **not interoperable** with the standard or each
other; store the two-letter source code alongside anything you keep.

What each actually removes differs, and the doc comments say so: for
Poly1305 it takes ChaCha20 out of the authentication path completely,
since Poly1305's security never depended on it. For XChaCha20 it removes
only the HChaCha20 assumption — the keystream is still ChaCha20.

The AEAD suites carry the choice on `AeadState`, and the one-shot tier
takes the same two arguments so a caller reading its suite out of a
header can read the sources from the same place:

```nim
  initAeadState(csXChaCha20AesGimliPoly1305, keys, nonce, 0'u16,
                cipherSource = sksBlake3, macSource = pksGimli)

  sealOf(csXChaCha20AesGimliPoly1305, keys, nonce, msg, 0'u16,
         cipherSource = sksBlake3, macSource = pksGimli)
```

Both default to the standard route. Both are bound into `authFrame`
alongside the suite id, so two peers configured differently get a clean
authentication failure rather than silently decrypting to garbage —
that binding is what the `v3` in the frame's domain string marks.

## Test Group Mapping

| Group             | Source path                                 |
|-------------------|---------------------------------------------|
| core              | tyr.nim, helpers/, */material.nim           |
| custom_crypto     | ciphers/, kdfs/argon2, kdfs/kdf             |
| sha3/poly1305/aes | hashes/sha3/, macs/poly1305/, ciphers/aes/  |
| gimli/blake3      | ciphers/gimli/, hashes/blake3/              |
| derive_sources    | ciphers/chacha/xchacha20_derive, macs/poly1305/derive |
| x25519            | kems/x25519/                                |
| kyber/frodo/bike  | kems/{kyber,frodo,bike}/                    |
| ntru/saber        | kems/{ntru,saber}/                          |
| dilithium/falcon  | signatures/{dilithium,falcon}/              |
| sphincs/mceliece  | signatures/sphincs/, kems/mceliece/         |
| cipher_runtime    | ciphers/dynamic.nim                         |
