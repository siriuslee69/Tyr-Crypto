import ./[
  test_common,
  test_x25519_custom,
  test_x25519_simd,
  test_ed25519_custom,
  test_kyber_tyr,
  test_frodo_tyr,
  test_bike_tyr,
  test_dilithium_tyr,
  test_falcon_tyr,
  test_sphincs_tyr,
  test_mceliece_tyr,
  test_ntru_tyr,
  test_saber_tyr,
  test_certificate_codecs
]

when isMainModule:
  discard
