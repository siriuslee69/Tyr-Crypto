# HQC in Tyr

╭⟢ what this file is 🌊

A byte-level map of Tyr's pure-Nim HQC. It says what every byte on the
wire means, which file does which job, and how to check the result
against the published vectors. Read `docs/ALGORITHMS.md` first if you
only want the sizes and the speed.

Everything here follows the HQC specification of **2025-08-22**, the
revision NIST selected in March 2025 as the backup key exchange it plans
to standardise beside ML-KEM.

---

## 1. Words this document uses ʕ•́ᴥ•̀ʔっ♡

Every technical term is defined once, here, before it is used.

**Def. 1 — bit string.** A row of zeros and ones of a fixed length. HQC's
are long: 17,669 bits for HQC-1. Tyr stores one as 64 bits per machine
word, lowest bit first.

**Def. 2 — weight.** How many 1-bits a bit string has. A string of 17,669
bits with 66 ones has *weight 66*. HQC calls such a string **sparse**.

**Def. 3 — codeword.** A bit string produced by an error-correcting code.
Codewords are chosen far apart from each other, so a damaged codeword can
still be matched to the right one.

**Def. 4 — product.** Two bit strings multiplied as polynomials, then
folded so the answer is the same length as the inputs. There is no
carrying: adding is exclusive-or.

**Def. 5 — KEM.** Key encapsulation mechanism. Two parties end up holding
the same 32 secret bytes, having sent only a public key one way and a
ciphertext the other way.

**Def. 6 — implicit rejection.** Handing back a plausible but different
secret when a ciphertext is wrong, instead of reporting an error. It
denies an attacker the yes/no answer they were fishing for.

---

## 2. What HQC actually computes 🐦‍🔥

**Example 1 — the key.** Pick a long random bit string `h`. Pick two
sparse secret strings `x` and `y`. Publish

```
    s  =  x  +  y·h
```

Recovering `x` and `y` from `h` and `s` means finding a sparse solution
to a huge system of equations. That is the hard problem, and no quantum
algorithm is known for it.

**Example 2 — sending a message.** Pick three more sparse strings `r1`,
`r2` and `e`. Send

```
    u  =  r1  +  r2·h
    v  =  codeword(m)  +  Truncate( r2·s  +  e )
```

**Example 3 — reading it.** The holder of `y` computes

```
    v  -  Truncate(u·y)
      =  codeword(m)  +  Truncate( x·r2  +  r1·y  +  e )
                          \________________________/
                              sparse, so it is just NOISE
```

Every term involving `h` cancels. What is left is the codeword plus a
sparse error, which is exactly the kind of damage an error-correcting
code exists to repair.

---

## 3. The two codes, stacked ╭⟢

Neither code alone is enough, so HQC uses both:

```
   message m                                       k bytes
      |
      |  Reed-Solomon: append 2·delta check bytes
      v
   codeword                                       n1 bytes
      |
      |  Reed-Muller: each byte becomes n2 bits,
      |  as a 128-bit word repeated a few times
      v
   codeword                                  n1 · n2 bits
      |
      |  bury in sparse noise -> this is `v`
      v
   ciphertext half
```

Reed-Muller survives very noisy bits but guesses wrong now and then.
Reed-Solomon almost never guesses wrong but cannot cope with bit-level
noise. Stacked, each covers the other's weakness.

Concrete numbers for HQC-1:

```
   16 message bytes
     -> 46-byte Reed-Solomon codeword (30 check bytes, 16 message bytes)
     -> 46 blocks of 384 bits          = 17,664 bits
   each 384-bit block is one 128-bit codeword written three times
   about 6,300 of those 17,664 bits arrive flipped
   each block therefore carries roughly 137 wrong bits out of 384
   two different 384-bit codewords differ in 192 places, so 137 is
     comfortably closer to the right one than to any other
```

---

## 4. Exact byte layouts ⌜guide⌟

Sizes below are HQC-1. Replace the numbers from the table in section 5
for the other two parameter sets. Every multi-byte field is plain bytes,
lowest bit of a bit string first; there are no integers to byte-swap.

### 4.1 Public key — 2,241 bytes

```
   +----------------------+-------------------------------------------+
   |      seed_ek         |                  s                        |
   |      32 bytes        |               2,209 bytes                 |
   +----------------------+-------------------------------------------+
   0                     32                                        2241
```

- `seed_ek` — the 32 bytes that `h` is regrown from. Storing the seed
  instead of `h` itself halves the public key.
- `s` — the 17,669-bit string `x + y·h`, packed 8 bits per byte. The top
  3 bits of the last byte are always zero.

### 4.2 Secret key — 2,321 bytes

```
   +------------------------+----------+---------+----------+
   |       public key       | seed_dk  |  sigma  | seed_kem |
   |       2,241 bytes      | 32 bytes |16 bytes | 32 bytes |
   +------------------------+----------+---------+----------+
   0                      2241      2273      2289       2321
```

- The public key is repeated verbatim, so decapsulation can re-encrypt
  without being handed one.
- `seed_dk` — the 32 bytes `x` and `y` are regrown from. This is the
  whole secret; everything else is convenience.
- `sigma` — the rejection secret. Mixed into the fake shared secret
  returned for a bad ciphertext, so the fake cannot be predicted.
- `seed_kem` — the seed the entire key grew from, kept so a holder can
  regenerate the key. **Decapsulation never reads it.**

### 4.3 Ciphertext — 4,433 bytes

```
   +----------------------+----------------------+----------+
   |          u           |          v           |   salt   |
   |     2,209 bytes      |     2,208 bytes      | 16 bytes |
   +----------------------+----------------------+----------+
   0                    2209                   4417       4433
```

- `u` — 17,669 bits. Top 3 bits of its last byte are zero in an honest
  ciphertext. They are **not** masked on parsing: a ciphertext that sets
  them fails the re-encryption check and is implicitly rejected.
- `v` — 17,664 bits, a whole number of bytes with no padding.
- `salt` — 16 fresh random bytes, sent in the clear. They go into both
  the shared secret and the encryption randomness, so two encapsulations
  against the same key are unrelated even if the message repeats.

---

## 5. The three parameter sets ୨୧

| | HQC-1 | HQC-3 | HQC-5 |
|---|---|---|---|
| NIST category | 1 | 3 | 5 |
| `n` (bits) | 17,669 | 35,851 | 57,637 |
| `n1` (bytes) | 46 | 56 | 90 |
| `n2` (bits) | 384 | 640 | 640 |
| repeats per byte | 3 | 5 | 5 |
| `omega` (weight of x, y) | 66 | 100 | 131 |
| `omega_r` / `omega_e` | 75 | 114 | 149 |
| message bytes | 16 | 24 | 32 |
| `delta` (bytes repairable) | 15 | 16 | 29 |
| public key | 2,241 | 4,514 | 7,237 |
| secret key | 2,321 | 4,602 | 7,333 |
| ciphertext | 4,433 | 8,978 | 14,421 |
| shared secret | 32 | 32 | 32 |

These names are **not** the older `HQC-128 / HQC-192 / HQC-256`. Those
came from a superseded revision with different numbers, and keys are not
interchangeable between the two.

---

## 6. The five hashes and where each tag goes ❖

Every use of SHA3 or SHAKE appends one tag byte **after** its input, so
two different uses can never collide.

| name | function | input, in order | tag | output |
|---|---|---|---|---|
| XOF | SHAKE-256 | seed (32) | `01` | as much as asked for |
| `I` | SHA3-512 | seed (32) | `02` | 64 bytes: seed_dk, seed_ek |
| `H` | SHA3-256 | whole public key | `01` | 32 bytes |
| `G` | SHA3-512 | H(pk), message, salt | `00` | 64 bytes: K, then theta |
| `J` | SHA3-256 | H(pk), sigma, u, v, salt | `03` | 32 bytes: reject key |

`XOF` and `H` share the tag value `01` and never collide, because one is
SHAKE-256 and the other is SHA3-256 — different functions entirely.

---

## 7. Flow of one exchange ╭─ ❧

```
   ALICE                                          BOB
   -----                                          ---
   hqcTyrKeypair(hqc1)
     32 random bytes
       -> XOF -> seed_pke (32), sigma (16)
       -> I(seed_pke) -> seed_dk, seed_ek
       -> seed_dk -> XOF -> y, then x       (sparse, weight omega)
       -> seed_ek -> XOF -> h               (dense, uniform)
       -> s = x + y·h
     public key = seed_ek || s
     secret key = public key || seed_dk || sigma || seed_kem

        public key  ------------------------------->

                                   hqcTyrEncaps(hqc1, pk)
                                     random message m, random salt
                                     K, theta = G( H(pk), m, salt )
                                     theta -> XOF -> r2, e, r1
                                     u = r1 + r2·h
                                     v = codeword(m) + Truncate(r2·s + e)
                                     ciphertext = u || v || salt
                                     KEEP K

        <-----------------------------  ciphertext

   hqcTyrDecaps(hqc1, sk, ct)
     m' = decode( v - Truncate(u·y) )
     K', theta' = G( H(pk), m', salt )
     rebuild u', v' from m' and theta'
     Kbar = J( H(pk), sigma, u, v, salt )
     match = (u == u') and (v == v')          <- no branch, a mask
     return  K'  when match, else  Kbar
```

The rebuild step is the whole safety argument. A ciphertext that was not
produced honestly from some message cannot be rebuilt, so it gets `Kbar`
— which looks exactly like a real key and tells the sender nothing.

---

## 8. Module map ⟡

```
   src/tyr/kems/hqc.nim              public surface, nothing else
   src/tyr/kems/hqc/
     params.nim        the three parameter sets, and every derived size
     parsing.nim       where every byte of a key or ciphertext lives
     types.nim         HqcVec, the ciphertext halves, the returned shapes
     util.nim          words <-> bytes, wiping, truncation, comparison
     masks.nim         yes/no answers as bit patterns, never as branches
     gf.nim            arithmetic in GF(2^8): one byte times one byte
     fft.nim           evaluate one polynomial at all 256 byte values
     fft_radix.nim     the algebraic split the FFT descends through
     reed_solomon.nim  the outer code: repair whole wrong bytes
     rs_locate.nim     step 1-3 of decoding: WHICH bytes are wrong
     rs_repair.nim     step 4-5 of decoding: by HOW MUCH each is wrong
     reed_muller.nim   the inner code: one byte out of a noisy block
     code.nim          the two stacked, encode and decode
     gf2x.nim          Karatsuba product of two long bit strings
     symmetric.nim     the SHAKE-256 stream and the four hashes
     vector.nim        sampling a bit string of an exact weight
     pke.nim           keygen, encrypt, decrypt
     operations.nim    the KEM wrapper: FO transform, implicit rejection
```

Dependency order runs down that list. Nothing above imports anything
below it.

---

## 9. Two samplers, on purpose 🍣

HQC needs bit strings of an exact weight, and uses **two different**
methods to get them.

| | key generation | encryption |
|---|---|---|
| routine | `sampleFixedWeightKey` | `sampleFixedWeightEnc` |
| method | reject biased draws, reject repeats | draw a fixed count, repair repeats |
| bias | none | vanishingly small |
| running time | depends on the draws | always the same |

Encryption runs on data an attacker can influence, so a fixed amount of
work matters more there than perfect uniformity. Key generation runs on
nothing an attacker supplies, so an unbiased secret matters more. The
reference implementation makes the same split; liboqs records the key
generation timing variance as a known, accepted property of HQC.

Writing the chosen positions into the bit string is branch-free in both
cases: every output word is compared against every chosen position, and
a mask decides whether anything lands there. That is `w·n/64`
comparisons instead of `w` stores, and it leaves no trace in the memory
access pattern.

---

## 10. Checking it ✦

```sh
nimble test_hqc              # round trips, the coding layers, single KATs
nimble test_hqc_kat_full     # all 100 published records per parameter set
```

`test_hqc_kat.nim` rebuilds the published response file from scratch:

```
   entropy 00 01 02 ... 2F
       |
       |  SHAKE-256( entropy || 00 )
       v
   outer stream --- 48 bytes per record ---> seed
                                               |
                             SHAKE-256( seed || 00 )
                                               v
                                        inner stream
                                        [0 .. 31]   keypair randomness
                                        [32 ..  ]   message, then salt
```

Each record is printed as `count / seed / pk / sk / ct / ss` in upper-case
hexadecimal, and the SHA-256 of the whole transcript is compared against
`submodules/cNimWrapper/submodules/liboqs/tests/KATs/kem/kats.json`.

> **The workspace holds two liboqs checkouts.** The older one beside the
> repository still carries `HQC-128/192/256` from the superseded
> revision. Only the pinned submodule matches this port. The test points
> at the submodule for exactly that reason.

All 300 published records — 100 for each of HQC-1, HQC-3 and HQC-5 —
reproduce byte for byte.

---

## 11. What is deliberately not done yet ⌜guide⌟

- **No SIMD.** The product is scalar Karatsuba. A carry-less multiply
  instruction (`pclmulqdq` on x86, `pmull` on ARM) would speed the whole
  scheme up several times over, and is the obvious next step.
- **No `material.nim` entry.** HQC is reachable from the default,
  dynamic and single tiers, but not yet from the typed-material surface,
  which currently covers X25519, Kyber, Frodo, BIKE and McEliece.
- **No liboqs runtime cross-check.** HQC is checked against the published
  vectors, not against a running liboqs, because the liboqs build used
  elsewhere in this repository predates this HQC revision.
- **Key generation timing varies.** See section 9. It matches the
  reference implementation, and it is confined to key generation.
