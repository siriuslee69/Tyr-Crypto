## ---------------------------------------------------------------
## NTRU Bindings <- PQClean reference and optional AVX2 entrypoints
## ---------------------------------------------------------------

import ./pqclean_common
import ../custom_crypto/asymmetric/pq/ntru/params

{.compile: "../../../submodules/pqclean_ntru_ref/ntruhps2048509_clean/cmov.c".}
{.compile: "../../../submodules/pqclean_ntru_ref/ntruhps2048509_clean/crypto_sort_int32.c".}
{.compile: "../../../submodules/pqclean_ntru_ref/ntruhps2048509_clean/kem.c".}
{.compile: "../../../submodules/pqclean_ntru_ref/ntruhps2048509_clean/owcpa.c".}
{.compile: "../../../submodules/pqclean_ntru_ref/ntruhps2048509_clean/pack3.c".}
{.compile: "../../../submodules/pqclean_ntru_ref/ntruhps2048509_clean/packq.c".}
{.compile: "../../../submodules/pqclean_ntru_ref/ntruhps2048509_clean/poly.c".}
{.compile: "../../../submodules/pqclean_ntru_ref/ntruhps2048509_clean/poly_lift.c".}
{.compile: "../../../submodules/pqclean_ntru_ref/ntruhps2048509_clean/poly_mod.c".}
{.compile: "../../../submodules/pqclean_ntru_ref/ntruhps2048509_clean/poly_r2_inv.c".}
{.compile: "../../../submodules/pqclean_ntru_ref/ntruhps2048509_clean/poly_rq_mul.c".}
{.compile: "../../../submodules/pqclean_ntru_ref/ntruhps2048509_clean/poly_s3_inv.c".}
{.compile: "../../../submodules/pqclean_ntru_ref/ntruhps2048509_clean/sample.c".}
{.compile: "../../../submodules/pqclean_ntru_ref/ntruhps2048509_clean/sample_iid.c".}

{.compile: "../../../submodules/pqclean_ntru_ref/ntruhps2048677_clean/cmov.c".}
{.compile: "../../../submodules/pqclean_ntru_ref/ntruhps2048677_clean/crypto_sort_int32.c".}
{.compile: "../../../submodules/pqclean_ntru_ref/ntruhps2048677_clean/kem.c".}
{.compile: "../../../submodules/pqclean_ntru_ref/ntruhps2048677_clean/owcpa.c".}
{.compile: "../../../submodules/pqclean_ntru_ref/ntruhps2048677_clean/pack3.c".}
{.compile: "../../../submodules/pqclean_ntru_ref/ntruhps2048677_clean/packq.c".}
{.compile: "../../../submodules/pqclean_ntru_ref/ntruhps2048677_clean/poly.c".}
{.compile: "../../../submodules/pqclean_ntru_ref/ntruhps2048677_clean/poly_lift.c".}
{.compile: "../../../submodules/pqclean_ntru_ref/ntruhps2048677_clean/poly_mod.c".}
{.compile: "../../../submodules/pqclean_ntru_ref/ntruhps2048677_clean/poly_r2_inv.c".}
{.compile: "../../../submodules/pqclean_ntru_ref/ntruhps2048677_clean/poly_rq_mul.c".}
{.compile: "../../../submodules/pqclean_ntru_ref/ntruhps2048677_clean/poly_s3_inv.c".}
{.compile: "../../../submodules/pqclean_ntru_ref/ntruhps2048677_clean/sample.c".}
{.compile: "../../../submodules/pqclean_ntru_ref/ntruhps2048677_clean/sample_iid.c".}

{.compile: "../../../submodules/pqclean_ntru_ref/ntruhps4096821_clean/cmov.c".}
{.compile: "../../../submodules/pqclean_ntru_ref/ntruhps4096821_clean/crypto_sort_int32.c".}
{.compile: "../../../submodules/pqclean_ntru_ref/ntruhps4096821_clean/kem.c".}
{.compile: "../../../submodules/pqclean_ntru_ref/ntruhps4096821_clean/owcpa.c".}
{.compile: "../../../submodules/pqclean_ntru_ref/ntruhps4096821_clean/pack3.c".}
{.compile: "../../../submodules/pqclean_ntru_ref/ntruhps4096821_clean/packq.c".}
{.compile: "../../../submodules/pqclean_ntru_ref/ntruhps4096821_clean/poly.c".}
{.compile: "../../../submodules/pqclean_ntru_ref/ntruhps4096821_clean/poly_lift.c".}
{.compile: "../../../submodules/pqclean_ntru_ref/ntruhps4096821_clean/poly_mod.c".}
{.compile: "../../../submodules/pqclean_ntru_ref/ntruhps4096821_clean/poly_r2_inv.c".}
{.compile: "../../../submodules/pqclean_ntru_ref/ntruhps4096821_clean/poly_rq_mul.c".}
{.compile: "../../../submodules/pqclean_ntru_ref/ntruhps4096821_clean/poly_s3_inv.c".}
{.compile: "../../../submodules/pqclean_ntru_ref/ntruhps4096821_clean/sample.c".}
{.compile: "../../../submodules/pqclean_ntru_ref/ntruhps4096821_clean/sample_iid.c".}

{.compile: "../../../submodules/pqclean_ntru_ref/ntruhrss701_clean/cmov.c".}
{.compile: "../../../submodules/pqclean_ntru_ref/ntruhrss701_clean/kem.c".}
{.compile: "../../../submodules/pqclean_ntru_ref/ntruhrss701_clean/owcpa.c".}
{.compile: "../../../submodules/pqclean_ntru_ref/ntruhrss701_clean/pack3.c".}
{.compile: "../../../submodules/pqclean_ntru_ref/ntruhrss701_clean/packq.c".}
{.compile: "../../../submodules/pqclean_ntru_ref/ntruhrss701_clean/poly.c".}
{.compile: "../../../submodules/pqclean_ntru_ref/ntruhrss701_clean/poly_lift.c".}
{.compile: "../../../submodules/pqclean_ntru_ref/ntruhrss701_clean/poly_mod.c".}
{.compile: "../../../submodules/pqclean_ntru_ref/ntruhrss701_clean/poly_r2_inv.c".}
{.compile: "../../../submodules/pqclean_ntru_ref/ntruhrss701_clean/poly_rq_mul.c".}
{.compile: "../../../submodules/pqclean_ntru_ref/ntruhrss701_clean/poly_s3_inv.c".}
{.compile: "../../../submodules/pqclean_ntru_ref/ntruhrss701_clean/sample.c".}
{.compile: "../../../submodules/pqclean_ntru_ref/ntruhrss701_clean/sample_iid.c".}

when ntruPqcleanAvx2Build:
  {.passC: "-mavx2 -mbmi2".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhps2048509_avx2/cmov.c".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhps2048509_avx2/crypto_sort_int32.c".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhps2048509_avx2/kem.c".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhps2048509_avx2/owcpa.c".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhps2048509_avx2/pack3.c".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhps2048509_avx2/packq.c".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhps2048509_avx2/poly.c".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhps2048509_avx2/poly_lift.c".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhps2048509_avx2/poly_r2_inv.c".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhps2048509_avx2/poly_s3_inv.c".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhps2048509_avx2/sample.c".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhps2048509_avx2/sample_iid.c".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhps2048509_avx2/poly_mod_3_Phi_n.s".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhps2048509_avx2/poly_mod_q_Phi_n.s".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhps2048509_avx2/poly_r2_mul.s".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhps2048509_avx2/poly_rq_mul.s".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhps2048509_avx2/poly_rq_to_s3.s".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhps2048509_avx2/square_126_509_shufbytes.s".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhps2048509_avx2/square_15_509_shufbytes.s".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhps2048509_avx2/square_1_509_patience.s".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhps2048509_avx2/square_252_509_shufbytes.s".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhps2048509_avx2/square_30_509_shufbytes.s".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhps2048509_avx2/square_3_509_patience.s".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhps2048509_avx2/square_63_509_shufbytes.s".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhps2048509_avx2/square_6_509_patience.s".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhps2048509_avx2/vec32_sample_iid.s".}

  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhps2048677_avx2/cmov.c".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhps2048677_avx2/crypto_sort_int32.c".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhps2048677_avx2/kem.c".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhps2048677_avx2/owcpa.c".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhps2048677_avx2/pack3.c".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhps2048677_avx2/packq.c".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhps2048677_avx2/poly.c".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhps2048677_avx2/poly_lift.c".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhps2048677_avx2/poly_r2_inv.c".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhps2048677_avx2/poly_s3_inv.c".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhps2048677_avx2/sample.c".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhps2048677_avx2/sample_iid.c".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhps2048677_avx2/poly_mod_3_Phi_n.s".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhps2048677_avx2/poly_mod_q_Phi_n.s".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhps2048677_avx2/poly_r2_mul.s".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhps2048677_avx2/poly_rq_mul.s".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhps2048677_avx2/poly_rq_to_s3.s".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhps2048677_avx2/square_10_677_shufbytes.s".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhps2048677_avx2/square_168_677_shufbytes.s".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhps2048677_avx2/square_1_677_patience.s".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhps2048677_avx2/square_21_677_shufbytes.s".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhps2048677_avx2/square_2_677_patience.s".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhps2048677_avx2/square_336_677_shufbytes.s".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhps2048677_avx2/square_3_677_patience.s".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhps2048677_avx2/square_42_677_shufbytes.s".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhps2048677_avx2/square_5_677_patience.s".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhps2048677_avx2/square_84_677_shufbytes.s".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhps2048677_avx2/vec32_sample_iid.s".}

  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhps4096821_avx2/cmov.c".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhps4096821_avx2/crypto_sort_int32.c".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhps4096821_avx2/kem.c".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhps4096821_avx2/owcpa.c".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhps4096821_avx2/pack3.c".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhps4096821_avx2/packq.c".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhps4096821_avx2/poly.c".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhps4096821_avx2/poly_lift.c".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhps4096821_avx2/poly_r2_inv.c".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhps4096821_avx2/poly_s3_inv.c".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhps4096821_avx2/sample.c".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhps4096821_avx2/sample_iid.c".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhps4096821_avx2/poly_mod_3_Phi_n.s".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhps4096821_avx2/poly_mod_q_Phi_n.s".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhps4096821_avx2/poly_r2_mul.s".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhps4096821_avx2/poly_rq_mul.s".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhps4096821_avx2/poly_rq_to_s3.s".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhps4096821_avx2/square_102_821_shufbytes.s".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhps4096821_avx2/square_12_821_shufbytes.s".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhps4096821_avx2/square_1_821_patience.s".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhps4096821_avx2/square_204_821_shufbytes.s".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhps4096821_avx2/square_24_821_shufbytes.s".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhps4096821_avx2/square_3_821_patience.s".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhps4096821_avx2/square_408_821_shufbytes.s".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhps4096821_avx2/square_51_821_shufbytes.s".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhps4096821_avx2/square_6_821_patience.s".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhps4096821_avx2/vec32_sample_iid.s".}

  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhrss701_avx2/cmov.c".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhrss701_avx2/kem.c".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhrss701_avx2/owcpa.c".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhrss701_avx2/pack3.c".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhrss701_avx2/packq.c".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhrss701_avx2/poly.c".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhrss701_avx2/poly_r2_inv.c".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhrss701_avx2/poly_s3_inv.c".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhrss701_avx2/sample.c".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhrss701_avx2/sample_iid.c".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhrss701_avx2/poly_lift.s".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhrss701_avx2/poly_mod_3_Phi_n.s".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhrss701_avx2/poly_mod_q_Phi_n.s".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhrss701_avx2/poly_r2_mul.s".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhrss701_avx2/poly_rq_mul.s".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhrss701_avx2/poly_rq_to_s3.s".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhrss701_avx2/square_12_701_shufbytes.s".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhrss701_avx2/square_15_701_shufbytes.s".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhrss701_avx2/square_168_701_shufbytes.s".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhrss701_avx2/square_1_701_patience.s".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhrss701_avx2/square_27_701_shufbytes.s".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhrss701_avx2/square_336_701_shufbytes.s".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhrss701_avx2/square_3_701_patience.s".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhrss701_avx2/square_42_701_shufbytes.s".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhrss701_avx2/square_6_701_patience.s".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhrss701_avx2/square_84_701_shufbytes.s".}
  {.compile: "../../../submodules/pqclean_ntru_ref/ntruhrss701_avx2/vec32_sample_iid.s".}

proc ntruHps2048509CleanKeypair*(pk, sk: ptr uint8): cint {.cdecl,
  importc: "PQCLEAN_NTRUHPS2048509_CLEAN_crypto_kem_keypair".}
proc ntruHps2048509CleanEnc*(ct, ss, pk: ptr uint8): cint {.cdecl,
  importc: "PQCLEAN_NTRUHPS2048509_CLEAN_crypto_kem_enc".}
proc ntruHps2048509CleanDec*(ss, ct, sk: ptr uint8): cint {.cdecl,
  importc: "PQCLEAN_NTRUHPS2048509_CLEAN_crypto_kem_dec".}

proc ntruHps2048677CleanKeypair*(pk, sk: ptr uint8): cint {.cdecl,
  importc: "PQCLEAN_NTRUHPS2048677_CLEAN_crypto_kem_keypair".}
proc ntruHps2048677CleanEnc*(ct, ss, pk: ptr uint8): cint {.cdecl,
  importc: "PQCLEAN_NTRUHPS2048677_CLEAN_crypto_kem_enc".}
proc ntruHps2048677CleanDec*(ss, ct, sk: ptr uint8): cint {.cdecl,
  importc: "PQCLEAN_NTRUHPS2048677_CLEAN_crypto_kem_dec".}

proc ntruHps4096821CleanKeypair*(pk, sk: ptr uint8): cint {.cdecl,
  importc: "PQCLEAN_NTRUHPS4096821_CLEAN_crypto_kem_keypair".}
proc ntruHps4096821CleanEnc*(ct, ss, pk: ptr uint8): cint {.cdecl,
  importc: "PQCLEAN_NTRUHPS4096821_CLEAN_crypto_kem_enc".}
proc ntruHps4096821CleanDec*(ss, ct, sk: ptr uint8): cint {.cdecl,
  importc: "PQCLEAN_NTRUHPS4096821_CLEAN_crypto_kem_dec".}

proc ntruHrss701CleanKeypair*(pk, sk: ptr uint8): cint {.cdecl,
  importc: "PQCLEAN_NTRUHRSS701_CLEAN_crypto_kem_keypair".}
proc ntruHrss701CleanEnc*(ct, ss, pk: ptr uint8): cint {.cdecl,
  importc: "PQCLEAN_NTRUHRSS701_CLEAN_crypto_kem_enc".}
proc ntruHrss701CleanDec*(ss, ct, sk: ptr uint8): cint {.cdecl,
  importc: "PQCLEAN_NTRUHRSS701_CLEAN_crypto_kem_dec".}

when ntruPqcleanAvx2Build:
  proc ntruHps2048509Avx2Keypair*(pk, sk: ptr uint8): cint {.cdecl,
    importc: "PQCLEAN_NTRUHPS2048509_AVX2_crypto_kem_keypair".}
  proc ntruHps2048509Avx2Enc*(ct, ss, pk: ptr uint8): cint {.cdecl,
    importc: "PQCLEAN_NTRUHPS2048509_AVX2_crypto_kem_enc".}
  proc ntruHps2048509Avx2Dec*(ss, ct, sk: ptr uint8): cint {.cdecl,
    importc: "PQCLEAN_NTRUHPS2048509_AVX2_crypto_kem_dec".}

  proc ntruHps2048677Avx2Keypair*(pk, sk: ptr uint8): cint {.cdecl,
    importc: "PQCLEAN_NTRUHPS2048677_AVX2_crypto_kem_keypair".}
  proc ntruHps2048677Avx2Enc*(ct, ss, pk: ptr uint8): cint {.cdecl,
    importc: "PQCLEAN_NTRUHPS2048677_AVX2_crypto_kem_enc".}
  proc ntruHps2048677Avx2Dec*(ss, ct, sk: ptr uint8): cint {.cdecl,
    importc: "PQCLEAN_NTRUHPS2048677_AVX2_crypto_kem_dec".}

  proc ntruHps4096821Avx2Keypair*(pk, sk: ptr uint8): cint {.cdecl,
    importc: "PQCLEAN_NTRUHPS4096821_AVX2_crypto_kem_keypair".}
  proc ntruHps4096821Avx2Enc*(ct, ss, pk: ptr uint8): cint {.cdecl,
    importc: "PQCLEAN_NTRUHPS4096821_AVX2_crypto_kem_enc".}
  proc ntruHps4096821Avx2Dec*(ss, ct, sk: ptr uint8): cint {.cdecl,
    importc: "PQCLEAN_NTRUHPS4096821_AVX2_crypto_kem_dec".}

  proc ntruHrss701Avx2Keypair*(pk, sk: ptr uint8): cint {.cdecl,
    importc: "PQCLEAN_NTRUHRSS701_AVX2_crypto_kem_keypair".}
  proc ntruHrss701Avx2Enc*(ct, ss, pk: ptr uint8): cint {.cdecl,
    importc: "PQCLEAN_NTRUHRSS701_AVX2_crypto_kem_enc".}
  proc ntruHrss701Avx2Dec*(ss, ct, sk: ptr uint8): cint {.cdecl,
    importc: "PQCLEAN_NTRUHRSS701_AVX2_crypto_kem_dec".}
