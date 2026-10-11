# NuGimli Cascade Test Vectors

Design revision 2 (2026-10-11): the lane swap hits every even chunk.
Every output below changed with it; vectors from before that date belong
to revision 1 and no longer match. See docs/NUGIMLI_REVIEW.md 14.1.

The complete machine-readable vectors are stored in
`evaluation/tests/nugimli_cascade_vectors.nim`. That file contains every 32-bit output
word for Cascade-512, Cascade-1024, and Cascade-2048.

## Representation

- State word `0` is serialized first.
- Every `uint32` word is serialized least-significant byte first.
- Cascade-512 uses 16 words and 24 rounds.
- Cascade-1024 uses 32 words and 28 rounds.
- Cascade-2048 uses 64 words and 32 rounds.

## Inputs

For word index `i`, beginning at zero:

```text
plaintext[i] = (i * 0x01020304) xor 0xA5A5A5A5
key[i]       = ((i + 1) * 0x9E3779B9) xor 0x3C6EF372
```

Two outputs are recorded for each width:

```text
permutation = CascadePermute(plaintext)
ciphertext  = key xor CascadePermute(plaintext xor key)
```

The tests verify all of the following against the complete arrays:

1. Optimized permutation output.
2. Portable scalar permutation output.
3. Direct reference permutation output.
4. Keyed ciphertext output.
5. Optimized inverse recovery.
6. Direct reference inverse recovery.

## Cascade-512

```text
Permutation:
56BBD58A 34910144 788C8020 0BEBEF4E
B63FBBEB 47536A27 9ADE49DD 7A5F6538
CCC15519 DC87AE52 2C33BA26 8DD56950
308BE102 48C408CC 9DBBDF4C E7C3362B

Ciphertext:
74739F8A 89B17EE2 0FCB538A 5FAA38BA
6E536098 D27EDB4A 6A3893B7 8F20CCF4
610E442A AFCD857B 0BB51D55 F4980AC8
11875761 D2972108 975CEBDE 1438E216
```

The longer 1024- and 2048-bit arrays remain in the machine-readable vector
module to avoid maintaining duplicate copies. Tagged SHAKE256 derivation
vectors are frozen separately in `evaluation/tests/test_nugimli_domain.nim`.
