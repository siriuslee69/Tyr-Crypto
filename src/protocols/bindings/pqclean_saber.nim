## ----------------------------------------------------------------
## SABER Bindings <- PQClean reference and optional AVX2 entrypoints
## ----------------------------------------------------------------

import ./pqclean_common

{.compile: "../../../submodules/pqclean_saber_ref/lightsaber_clean/cbd.c".}
{.compile: "../../../submodules/pqclean_saber_ref/lightsaber_clean/kem.c".}
{.compile: "../../../submodules/pqclean_saber_ref/lightsaber_clean/pack_unpack.c".}
{.compile: "../../../submodules/pqclean_saber_ref/lightsaber_clean/poly.c".}
{.compile: "../../../submodules/pqclean_saber_ref/lightsaber_clean/poly_mul.c".}
{.compile: "../../../submodules/pqclean_saber_ref/lightsaber_clean/SABER_indcpa.c".}
{.compile: "../../../submodules/pqclean_saber_ref/lightsaber_clean/verify.c".}

{.compile: "../../../submodules/pqclean_saber_ref/saber_clean/cbd.c".}
{.compile: "../../../submodules/pqclean_saber_ref/saber_clean/kem.c".}
{.compile: "../../../submodules/pqclean_saber_ref/saber_clean/pack_unpack.c".}
{.compile: "../../../submodules/pqclean_saber_ref/saber_clean/poly.c".}
{.compile: "../../../submodules/pqclean_saber_ref/saber_clean/poly_mul.c".}
{.compile: "../../../submodules/pqclean_saber_ref/saber_clean/SABER_indcpa.c".}
{.compile: "../../../submodules/pqclean_saber_ref/saber_clean/verify.c".}

{.compile: "../../../submodules/pqclean_saber_ref/firesaber_clean/cbd.c".}
{.compile: "../../../submodules/pqclean_saber_ref/firesaber_clean/kem.c".}
{.compile: "../../../submodules/pqclean_saber_ref/firesaber_clean/pack_unpack.c".}
{.compile: "../../../submodules/pqclean_saber_ref/firesaber_clean/poly.c".}
{.compile: "../../../submodules/pqclean_saber_ref/firesaber_clean/poly_mul.c".}
{.compile: "../../../submodules/pqclean_saber_ref/firesaber_clean/SABER_indcpa.c".}
{.compile: "../../../submodules/pqclean_saber_ref/firesaber_clean/verify.c".}

when defined(avx2):
  {.passC: "-mavx2".}
  {.compile: "../../../submodules/pqclean_saber_ref/lightsaber_avx2/cbd.c".}
  {.compile: "../../../submodules/pqclean_saber_ref/lightsaber_avx2/kem.c".}
  {.compile: "../../../submodules/pqclean_saber_ref/lightsaber_avx2/pack_unpack.c".}
  {.compile: "../../../submodules/pqclean_saber_ref/lightsaber_avx2/poly.c".}
  {.compile: "../../../submodules/pqclean_saber_ref/lightsaber_avx2/poly_mul.c".}
  {.compile: "../../../submodules/pqclean_saber_ref/lightsaber_avx2/SABER_indcpa.c".}
  {.compile: "../../../submodules/pqclean_saber_ref/lightsaber_avx2/verify.c".}

  {.compile: "../../../submodules/pqclean_saber_ref/saber_avx2/cbd.c".}
  {.compile: "../../../submodules/pqclean_saber_ref/saber_avx2/kem.c".}
  {.compile: "../../../submodules/pqclean_saber_ref/saber_avx2/pack_unpack.c".}
  {.compile: "../../../submodules/pqclean_saber_ref/saber_avx2/poly.c".}
  {.compile: "../../../submodules/pqclean_saber_ref/saber_avx2/poly_mul.c".}
  {.compile: "../../../submodules/pqclean_saber_ref/saber_avx2/SABER_indcpa.c".}
  {.compile: "../../../submodules/pqclean_saber_ref/saber_avx2/verify.c".}

  {.compile: "../../../submodules/pqclean_saber_ref/firesaber_avx2/cbd.c".}
  {.compile: "../../../submodules/pqclean_saber_ref/firesaber_avx2/kem.c".}
  {.compile: "../../../submodules/pqclean_saber_ref/firesaber_avx2/pack_unpack.c".}
  {.compile: "../../../submodules/pqclean_saber_ref/firesaber_avx2/poly.c".}
  {.compile: "../../../submodules/pqclean_saber_ref/firesaber_avx2/poly_mul.c".}
  {.compile: "../../../submodules/pqclean_saber_ref/firesaber_avx2/SABER_indcpa.c".}
  {.compile: "../../../submodules/pqclean_saber_ref/firesaber_avx2/verify.c".}

proc lightSaberCleanKeypair*(pk, sk: ptr uint8): cint {.cdecl,
  importc: "PQCLEAN_LIGHTSABER_CLEAN_crypto_kem_keypair".}
proc lightSaberCleanEnc*(ct, ss, pk: ptr uint8): cint {.cdecl,
  importc: "PQCLEAN_LIGHTSABER_CLEAN_crypto_kem_enc".}
proc lightSaberCleanDec*(ss, ct, sk: ptr uint8): cint {.cdecl,
  importc: "PQCLEAN_LIGHTSABER_CLEAN_crypto_kem_dec".}

proc saberCleanKeypair*(pk, sk: ptr uint8): cint {.cdecl,
  importc: "PQCLEAN_SABER_CLEAN_crypto_kem_keypair".}
proc saberCleanEnc*(ct, ss, pk: ptr uint8): cint {.cdecl,
  importc: "PQCLEAN_SABER_CLEAN_crypto_kem_enc".}
proc saberCleanDec*(ss, ct, sk: ptr uint8): cint {.cdecl,
  importc: "PQCLEAN_SABER_CLEAN_crypto_kem_dec".}

proc fireSaberCleanKeypair*(pk, sk: ptr uint8): cint {.cdecl,
  importc: "PQCLEAN_FIRESABER_CLEAN_crypto_kem_keypair".}
proc fireSaberCleanEnc*(ct, ss, pk: ptr uint8): cint {.cdecl,
  importc: "PQCLEAN_FIRESABER_CLEAN_crypto_kem_enc".}
proc fireSaberCleanDec*(ss, ct, sk: ptr uint8): cint {.cdecl,
  importc: "PQCLEAN_FIRESABER_CLEAN_crypto_kem_dec".}

when defined(avx2):
  proc lightSaberAvx2Keypair*(pk, sk: ptr uint8): cint {.cdecl,
    importc: "PQCLEAN_LIGHTSABER_AVX2_crypto_kem_keypair".}
  proc lightSaberAvx2Enc*(ct, ss, pk: ptr uint8): cint {.cdecl,
    importc: "PQCLEAN_LIGHTSABER_AVX2_crypto_kem_enc".}
  proc lightSaberAvx2Dec*(ss, ct, sk: ptr uint8): cint {.cdecl,
    importc: "PQCLEAN_LIGHTSABER_AVX2_crypto_kem_dec".}

  proc saberAvx2Keypair*(pk, sk: ptr uint8): cint {.cdecl,
    importc: "PQCLEAN_SABER_AVX2_crypto_kem_keypair".}
  proc saberAvx2Enc*(ct, ss, pk: ptr uint8): cint {.cdecl,
    importc: "PQCLEAN_SABER_AVX2_crypto_kem_enc".}
  proc saberAvx2Dec*(ss, ct, sk: ptr uint8): cint {.cdecl,
    importc: "PQCLEAN_SABER_AVX2_crypto_kem_dec".}

  proc fireSaberAvx2Keypair*(pk, sk: ptr uint8): cint {.cdecl,
    importc: "PQCLEAN_FIRESABER_AVX2_crypto_kem_keypair".}
  proc fireSaberAvx2Enc*(ct, ss, pk: ptr uint8): cint {.cdecl,
    importc: "PQCLEAN_FIRESABER_AVX2_crypto_kem_enc".}
  proc fireSaberAvx2Dec*(ss, ct, sk: ptr uint8): cint {.cdecl,
    importc: "PQCLEAN_FIRESABER_AVX2_crypto_kem_dec".}
