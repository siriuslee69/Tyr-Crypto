## --------------------------------------------------
## | Classic McEliece <- public surface
## --------------------------------------------------
##
## Post-quantum KEM built on binary Goppa codes. Very large public keys, very small ciphertexts.
##
## The full implementation lives in `./mceliece/`. This file is the
## list of what callers may use; it holds no logic of its own, so the
## algorithm's own files never need to think about the public API.
##
## ╭⟢ WARNING - 2026 attacks on the math itself (not on this code) ⚠
## │
## │  What happened:
## │    In August/September 2026 several papers found a way to recover the
## │    SECRET key from the PUBLIC key much faster than was thought possible.
## │    They attack binary Goppa codes - the math every McEliece build uses -
## │    so Tyr's own speed-ups (SIMD, transpose, masked row XOR) change nothing:
## │    the attacker never runs our code, only reads the public key.
## │
## │  How bad (bit operations an attacker needs, all papers still unreviewed):
## │
## │    claimed before 2026        Tyr sets (6688128f / 6960119f / 8192128f)
## │    ─────────────────────────  ──────────────────────────────────────────
## │    category 5  (~2^256)       Ghoshal-Ishai-Jain-Sun   ~2^140 .. 2^148
## │                               Weis                     ~2^99  .. 2^102
## │    (figures for the BSI-recommended sets, as quoted in the BSI note;
## │     memory access is not charged, so the real cost is somewhat higher)
## │
## │    2^128 is the floor for "category 1" (AES-128). Below it is "broken
## │    on paper". Nobody has run the attack at full size; no real key has
## │    been recovered.
## │
## │  What it means for Tyr users:
## │    - do NOT use McEliece alone. Always pair it with a classical KEM
## │      (X25519) or with ML-KEM / FrodoKEM, so both must fall.
## │    - for new designs prefer ML-KEM or FrodoKEM (BSI: HQC once standard).
## │
## │  Sources:
## │    BSI, "Notes on recent developments concerning Classic McEliece",
## │      29 Sep 2026 (press release 1 Oct 2026):
## │      https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Crypto/Notes_Classic_McEliece.pdf
## │    Ghoshal, Ishai, Jain, Sun - Quasipolynomial Cryptanalysis of the
## │      McEliece Cryptosystem:        https://eprint.iacr.org/2026/1630
## │    Vedenev - distinguisher -> key recovery:  https://eprint.iacr.org/2026/1747
## │    Weis - Improving GIJS Key Recovery:       https://eprint.iacr.org/2026/1984
## │    Saarinen - TII-254 challenge solved:      https://eprint.iacr.org/2026/1986
## │
## ╰⟢ The compiler prints a short form of this. Silence it with
##    `-d:tyrMcElieceAttackAcknowledged` once you have read the above.

when not defined(tyrMcElieceAttackAcknowledged):
  {.warning: "Tyr: Classic McEliece is weakened by 2026 key-recovery attacks " &
    "(ePrint 2026/1630, 2026/1984; BSI note 29 Sep 2026): estimated cost " &
    "~2^99..2^148 instead of ~2^256 for the 6688128f/6960119f/8192128f sets. " &
    "Use it only in a hybrid with X25519/ML-KEM/FrodoKEM; prefer ML-KEM or " &
    "FrodoKEM for new designs. See src/tyr/kems/mceliece.nim. Silence with " &
    "-d:tyrMcElieceAttackAcknowledged.".}

import ./mceliece/operations

export operations
