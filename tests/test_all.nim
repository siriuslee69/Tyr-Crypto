import std/os

putEnv("LIBOQS_AUTO_BUILD", "yes")

include "test_common"
include "test_registry"
include "test_libsodium"
include "test_nimcrypto"
include "test_custom_crypto"
include "test_aes_ctr"
include "test_aes_gcm_compare"
include "test_gimli_sse"
include "test_gimli_vectors"
include "test_blake3_simd"
include "test_random_entropy"
include "test_blake3_stream"
include "test_wrapper"
include "test_xchacha20_gimli"
include "test_aes_gimli"
include "test_xchacha20_aes_gimli"
include "test_xchacha20_aes_gimli_poly1305"
include "test_xchacha20_simd"
include "test_otp"
include "test_chunky_crypto"
include "test_pin_key"
include "test_hybrid_kex_triple"
include "test_hybrid_kex_duo"
include "test_signatures"
include "test_liboqs"
include "test_openssl"

when isMainModule:
  discard
