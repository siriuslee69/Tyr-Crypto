import std/os

putEnv("LIBOQS_AUTO_BUILD", "yes")
putEnv("LIBSODIUM_AUTO_BUILD", "yes")

include "test_common"
include "test_registry"
include "test_libsodium"
include "test_nimcrypto"
include "test_custom_crypto"
include "test_sha3_custom"
include "test_poly1305_custom"
include "test_aes_ctr"
include "test_aes_gcm_compare"
include "test_gimli_sse"
include "test_gimli_vectors"
include "test_blake3_simd"
include "test_sha3_simd"
include "test_poly1305_simd"
include "test_random_entropy"
include "test_blake3_stream"
include "test_custom_hmac"
include "test_quick_api"
include "test_primitives_api"
include "test_xchacha20_simd"
include "test_otp"
include "test_hybrid_kex_triple"
include "test_hybrid_kex_duo"
include "test_mceliece_tyr"
include "test_signatures"
include "test_liboqs"
include "test_openssl"

when isMainModule:
  discard
