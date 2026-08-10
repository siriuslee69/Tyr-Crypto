import tyr_crypto

let
  msg = @[byte 'H', 'e', 'l', 'l', 'o']
  hash32 = blake3Hash(msg)
  hash64 = blake3Hash(msg, 64)
  keyed = blake3KeyedHash(hash32, msg)
  derived = blake3DeriveKey("Tyr-Crypto app v1", msg, 32)

echo "BLAKE3-256:   ", hash32.toHex
echo "BLAKE3-512:   ", hash64.toHex
echo "BLAKE3-keyed: ", keyed.toHex
echo "BLAKE3-KDF:   ", derived.toHex

let sha3_256 = sha3_256Hash(msg)
let sha3_512 = sha3_512Hash(msg)
echo "SHA3-256:     ", sha3_256.toHex
echo "SHA3-512:     ", sha3_512.toHex

let tag = poly1305Mac(hash32, msg)
echo "Poly1305 tag: ", tag.toHex
