include "test_common"
include "test_custom_crypto"
include "test_aes_ctr"
include "test_gimli_sse"
include "test_blake3_simd"
include "test_sha3_simd"
include "test_poly1305_simd"
include "test_xchacha20_simd"

when isMainModule:
  discard
