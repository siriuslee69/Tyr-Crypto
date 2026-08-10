# NuGimli Cascade Test Vectors

The complete machine-readable vectors are stored in
`tests/nugimli_cascade_vectors.nim`. That file contains every 32-bit output
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
CCEF72D6 B74EA8E4 E285DCD2 B25785D2
FC316E4F 9C79950F C6C89B5D DE0B1CEA
C1658F25 CAF58914 83D7F7C3 57DE0827
EC142F5B 4A9661A6 26E8082E D2BA1D20

Ciphertext:
10F2522E 7A3904B0 373E6024 3E13E71A
0BD99072 24376A77 009FDCF9 FC82996B
E959CE77 A158E1DE CEE1208D 2A60288E
A1B6E6FF 158B0C80 A2FECBEE E92399E3
```

The longer 1024- and 2048-bit arrays remain in the machine-readable vector
module to avoid maintaining duplicate copies. Tagged SHAKE256 derivation
vectors are frozen separately in `tests/test_nugimli_domain.nim`.
