# Tyr-Crypto Code Layout

## Repo Map

```text
+------------------------------+---------------------------------------------+
| Path                         | Responsibility                              |
+------------------------------+---------------------------------------------+
| src/tyr_crypto.nim           | Public export facade                        |
| src/protocols/config/        | config.toml and userconfig.toml parsing     |
| src/protocols/wrapper/       | Typed public operation API                  |
| src/protocols/custom_crypto/ | Pure-Nim primitive implementations          |
| src/protocols/bindings/      | Optional native ABI bindings                |
| src/protocols/builders/      | Native dependency build helpers             |
| bindings/js/                 | Wasm loader and TypeScript declarations     |
| tests/                       | Unit, vector, parity, and harness tests     |
| tools/                       | Nim build, bench, harness, and report tools |
| submodules/                  | Pinned upstream source dependencies         |
| .iron/                       | Repo coordination metadata and conventions  |
+------------------------------+---------------------------------------------+
```

## Dependency Flow

```text
User code
   |
   v
src/tyr_crypto.nim
   |
   +--> wrapper/basic_api.nim
   |       |
   |       +--> wrapper/helpers/*
   |       +--> custom_crypto/*
   |       +--> bindings/* when enabled by -d:has*
   |
   +--> protocols/config/tyr_config.nim
   |
   +--> custom_crypto compatibility facades
```

## Primitive Layout

```text
custom_crypto/
   |
   +--> symmetric/
   |       +--> aes, blake3, chacha, gimli, hmac, otp, poly1305, random, sha3
   |
   +--> asymmetric/
           +--> none_pq/x25519*
           +--> pq/{bike,dilithium,falcon,frodo,kyber,mceliece,ntru,saber,sphincs}
```

Compatibility facades stay at `src/protocols/custom_crypto/*.nim` so existing imports keep working. New implementation code should go into the class-specific folders.

## Data Flow

```text
raw bytes/config input
   |
   v
sanitize/parse
   |
   v
typed material or config truth state
   |
   v
actor operation: hash/encrypt/sign/encapsulate
   |
   v
typed output bytes, signature, tag, or KEM envelope
```

## Naming Rules

```text
+--------------------+------------------------------------------+
| Name shape         | Meaning                                  |
+--------------------+------------------------------------------+
| *Tyr*              | Local pure-Nim implementation path       |
| unsuffixed backend | Optional native backend path             |
| *M                 | Typed material object for basic_api      |
| *SendM/*OpenM      | KEM sender/opening material              |
| *SignM/*VerifyM    | Signature material                       |
+--------------------+------------------------------------------+
```
