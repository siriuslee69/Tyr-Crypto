# ⟦ NuGimli Cascade ⟧ Design Review 🌲

Review date: 2026-10-10. Reviewed commit: `2f8d30c` plus the fixes listed in
chapter 13. Scope: `src/tyr/ciphers/nugimli/`, its tests, and its evaluation
tools.

```
 design revision   lane swap (step 2) hits     in src/ since   numbers in
 ───────────────   ─────────────────────────   ─────────────   ──────────────
 1  first design   ONE chunk: (5r) and (C-1)   start           chapters 4-7
 2  current        EVERY EVEN chunk: 0,2,4...  2026-10-11      chapter 14.1
```

Chapters 4 to 7 measure the FIRST design; that is where its weak spot was
found. Chapter 14.1 measures both side by side. Every output changed with
revision 2, so the vectors were made anew.

```
╭─ ❧ 0  Verdict                                   🍵
├─ ❧ 1  What NuGimli is, in plain words           🌱
├─ ❧ 2  Exact specification                       📐
├─ ❧ 3  Is the code right?                        🔍
├─ ❧ 4  Structure: lanes, constants, symmetry     🧱
├─ ❧ 5  Diffusion: how fast a change spreads      🌊
├─ ❧ 6  Differential trails                       🧵
├─ ❧ 7  Zero-sum (integral) distinguishers        ⚖️
├─ ❧ 8  The key layer (Even-Mansour)              🔑
├─ ❧ 9  Width transitions (SHAKE256 derivation)   🔀
├─ ❧ 10 Side channels and memory                  🕯️
├─ ❧ 11 Speed                                     🐎
├─ ❧ 12 What the repo's own evidence can and cannot show
├─ ❧ 13 Findings and fixes                        🛠️
├─ ❧ 14 Recommendations (14.1 lane-swap fix)      🧭
╰─ ❧ 15 How the numbers were made                 🧪
```

---

## ╭⟢ 0 Verdict 🍵

```
┌────────────────────────────────┬──────────────────────────────────────────┐
│ question                       │ answer                                   │
├────────────────────────────────┼──────────────────────────────────────────┤
│ Does the code do what the      │ YES. An independent re-implementation,   │
│ specification says?            │ the repo code (portable and SIMD) and    │
│                                │ the published vectors agree bit-for-bit. │
│ Is P a permutation (can it be  │ YES, proven (chapter 3), and checked.    │
│ undone exactly)?               │                                          │
│ Is it a secure cipher?         │ UNKNOWN. Nobody has published an attack, │
│                                │ but nobody has published analysis        │
│                                │ either. The design inherits Gimli's slow │
│                                │ mixing between columns, the property     │
│                                │ that full-round Gimli distinguishers     │
│                                │ were built on.                           │
│ Simple attacks reach how far?  │ 512: ~12-13 of 24 rounds                 │
│ (this review, cheap tools)     │ 1024: ~11-19 of 28 rounds                │
│                                │ 2048: ~15-23 of 32 rounds                │
│ Ready for real data?           │ NO. Keep it experimental (the README     │
│                                │ already says so).                        │
└────────────────────────────────┴──────────────────────────────────────────┘
```

(ꐦ°᷄д°᷅) The wider profiles have proportionally LESS reserve than the
512-bit one. The round count grows by 4 per doubling of width; the rounds
that diffusion needs grow faster (chapter 5).

---

## ╭⟢ 1 What NuGimli is, in plain words 🌱

Think of a deck of cards that is shuffled by a fixed recipe. Anyone can
shuffle it, and anyone can un-shuffle it, because the recipe is public. The
recipe is only useful if the result looks completely random to someone who
does not know where each card started.

NuGimli is such a recipe for 512, 1024 or 2048 bits. To turn it into a
cipher, a secret key is mixed in before and after the shuffle.

**Def. 1 — word.** 32 bits, stored least significant byte first.

**Def. 2 — chunk.** 4 consecutive words = 128 bits. Chunk `c` holds words
`4c, 4c+1, 4c+2, 4c+3`.

**Def. 3 — lane.** Position of a word inside its chunk: lane `j` is every
word whose index leaves remainder `j` when divided by 4. A lane runs through
all chunks like a column through the rows of a table.

```
                 lane 0   lane 1   lane 2   lane 3
   chunk 0      word 0   word 1   word 2   word 3
   chunk 1      word 4   word 5   word 6   word 7
   chunk 2      word 8   word 9   word 10  word 11
   ...
   chunk C-1    ...                         word N-1

   N = words: 16 / 32 / 64      C = chunks: 4 / 8 / 16
```

**Def. 4 — box.** The original Gimli column operation. It takes three
words (one from each of three chunks, same lane) and returns three new
words. It is the only non-linear step: the only place where bits are
combined with AND or OR.

**Def. 5 — permutation P.** All rounds applied in order. A permutation can
be run backwards exactly: `P^-1(P(x)) = x`.

**Def. 6 — Even-Mansour cipher.** `C = K xor P(X xor K)` with the same key
`K` on both sides (chapter 8).

---

## ╭⟢ 2 Exact specification 📐

### 2.1 The box (per lane `i`, chunks `a < b < c`)

```
   x = rotl(S[a][i], 24)          rotl = rotate left inside 32 bits
   y = rotl(S[b][i],  9)
   z =      S[c][i]

   S[c][i] = x xor (z << 1) xor ((y and z) << 2)
   S[b][i] = y xor  x       xor ((x or  z) << 1)
   S[a][i] = z xor  y       xor ((x and y) << 3)
```

This is Gimli's SP-box unchanged. `<<` is a shift: bits pushed past bit 31
are lost.

### 2.2 One forward round `r`

Rounds run from `r = R` down to `r = 1`. `R` = 24 / 28 / 32.

```
 ┌──────────────────────────────────────────────────────────────────────┐
 │ step 1  SWEEP      box(0,1,2), box(1,2,3), ..., box(C-3,C-2,C-1)     │
 │                    left to right; windows OVERLAP, so each box sees  │
 │                    the previous box's output                         │
 │ step 2  LANE SWAP  every even chunk t = 0, 2, 4, ... (revision 2)    │
 │                    r mod 4 = 0 : lanes 0<->1, 2<->3 inside chunk t   │
 │                    r mod 4 = 2 : lanes 0<->2, 1<->3 inside chunk t   │
 │                    r odd       : nothing                             │
 │                    (revision 1: only chunk t = (5r) and (C-1))       │
 │ step 3  TWIST      every word rotl 1                                 │
 │ step 4  CONSTANTS  d = 0x43415343 xor (N*32)                         │
 │                    word 0   ^= d xor r                               │
 │                    word N-1 ^= rotl(d xor N, r and 31)               │
 │ step 5  BUTTERFLY  distance = 2^((r-1) mod log2(C))                  │
 │                    chunk i <-> chunk (i xor distance)                │
 └──────────────────────────────────────────────────────────────────────┘
```

Example 1 — the butterfly for 512 bits (C = 4):

```
   r even -> distance 2 :  [0][1][2][3]  ->  [2][3][0][1]
   r odd  -> distance 1 :  [0][1][2][3]  ->  [1][0][3][2]
```

Example 2 — where the lane swap landed in revision 1. The swap only happens
when `r` is even, so `5r` is even, so the target chunk is always EVEN:

```
   width   lanes 0<->1 (r mod 4 = 0)   lanes 0<->2 (r mod 4 = 2)
   512     chunk 0 only                chunk 2 only
   1024    chunks 0, 4                 chunks 2, 6
   2048    chunks 0, 4, 8, 12          chunks 2, 6, 10, 14
```

The butterfly moves data between positions, so all data is visited over
time. The multiplier `5` was probably meant to spread the target over all
chunks; with even `r` it reaches only half of them. Revision 2 drops the
multiplier and swaps all even chunks at once:

```
   width   revision 2, every even round
   512     chunks 0, 2
   1024    chunks 0, 2, 4, 6
   2048    chunks 0, 2, 4, ..., 14
```

### 2.3 Inverse round

Same five steps in reverse order: butterfly (it undoes itself), constants
(xor undoes itself), twist with `rotr 1`, lane swap (undoes itself), then
the sweep right to left with the inverse box.

### 2.4 The inverse box

Gimli's box is "triangular": output bit `k` depends on input bit `k` only
through plain xor, and on other bits only at positions BELOW `k` (all
non-linear terms are shifted LEFT). So the inputs can be recovered bit by
bit from the bottom:

```
   bit 0 of x  <-  bit 0 of out_c                      (nothing below)
   bit 0 of y  <-  bit 0 of out_b, bit 0 of x
   bit 0 of z  <-  bit 0 of out_a, bit 0 of y
   bit 1 of x  <-  bit 1 of out_c, bits 0 of y, z
   ...
```

The code repeats the three forward formulas 32 times. Each pass fixes at
least one more bit, so after 32 passes all 32 bits are right, whatever the
starting values were. This is correct (checked in chapter 3) and its
running time does not depend on the data. It is also why decryption costs
about 7-10x more than encryption (chapter 11).

---

## ╭⟢ 3 Is the code right? 🔍

A second implementation was written from chapter 2 alone, on purpose done
differently: the butterfly as "chunk index xor distance", and the inverse
box as an explicit bit-by-bit solve instead of the 32-pass loop.

```
 check                                                         result
 ────────────────────────────────────────────────────────────  ──────────
 inverse box, 200 000 random inputs, both inverse methods       0 errors
 512 / 1024 / 2048 permutation vs published vectors            match
 512 / 1024 / 2048 keyed ciphertext vs published vectors       match
 model vs repo portable code vs repo SIMD code, 200 random     match
 states per width, forward AND inverse
 repo tests: -d:tyrSimd=scalar, sse2, native                   all pass
 README example via `import tyr`                               FAILED -> fixed (13.1)
```

**Proof sketch that P is a permutation.** Each step is a bijection: the box
by the triangular argument above, rotations and swaps by moving bits
without losing any, xor with a constant by undoing itself. A chain of
bijections is a bijection.

---

## ╭⟢ 4 Structure: lanes, constants, symmetry 🧱

### 4.1 The lanes are four nearly separate machines

The box works lane by lane. The twist works word by word. The butterfly
moves WHOLE chunks, so a word keeps its lane. Only two things move data
between lanes:

```
   step         moves data across lanes?   how much per round
   ───────────  ─────────────────────────  ────────────────────────────
   sweep        no                         -
   lane swap    YES                        ONE chunk, only in even rounds
   twist        no                         -
   constants    no (adds into lane 0, 3)   -
   butterfly    no                         -
```

So per even round, the share of the state that changes lanes is:

```
   Gimli-384 (reference)   1 row of 3      = 33 %
   NuGimli-512             1 chunk of 4    = 25 %
   NuGimli-1024            1 chunk of 8    = 12.5 %
   NuGimli-2048            1 chunk of 16   =  6.25 %
```

In odd rounds the four lanes do not touch each other at all.

This matters because Gimli's own weakness lives exactly here. Published
attacks on Gimli (Hamburg 2017, "Cryptanalysis of 22 1/2 rounds of Gimli";
Flórez Gutiérrez, Leurent, Naya-Plasencia, Perrin, Schrottenloher and
Sibleyras, ASIACRYPT 2020, "New results on Gimli: full-permutation
distinguishers and improved collisions") use the slow mixing between
columns; the second paper distinguishes the FULL 24-round Gimli
permutation from a random one. NuGimli makes the lanes wider and the
cross-lane traffic thinner, and the wider the profile, the thinner.

Measured: rounds until a single flipped input bit has reached all four
lanes (chapter 15, method D):

```
   width   forward   backward
   512     5         6
   1024    5         6
   2048    7         8
```

### 4.2 Round constants: better than Gimli

Gimli adds a constant only every 4th round, into one word. NuGimli adds two
per round, different every round and different per width. That blocks:

- **slide attacks** (no two rounds are the same function);
- **lane-symmetry attacks.** Measured: a state with mirrored lanes loses the
  mirror within 2-5 rounds without any help from the attacker. One partial
  symmetry ("lane 1 = lane 2") survives 3 rounds, because both constants
  land in lanes 0 and 3.

```
   start symmetry      rounds until it looks random (512 / 1024 / 2048)
   lane0=1, lane2=3    2 / 3 / 3
   lane0=2, lane1=3    2 / 3 / 3
   lane0=3, lane1=2    5 / 5 / 5     (lane1=2 part holds 3 rounds)
```

(｡•̀ᴗ-)✧ This is a genuine improvement over Gimli, and it closes the door the
full-Gimli distinguisher came through. It does not close the lane-traffic
problem of 4.1.

### 4.3 Linear invariants

The repo's evaluation builds full-rank GF(2) matrices from `x xor P(x)`.
That correctly rules out any fixed bit mask whose parity P never changes.
It does not rule out non-linear invariants. That is normal, and the repo
says so.

---

## ╭⟢ 5 Diffusion: how fast a change spreads 🌊

**Def. 7 — full diffusion after k rounds.** Every output bit has flipped at
least once when any single input bit is flipped (64 random states per input
bit; a fair coin fails to flip 64 times in a row with chance 2^-64).

Forward = the encryption direction. Backward = the decryption direction (P^-1).
"own start" = the rounds the cipher actually runs first. "worst" = the
slowest window of k consecutive rounds anywhere in the schedule. An
attacker may pick any window.

```
 width  rounds │ fwd own  fwd worst │ bwd own  bwd worst │ fwd+bwd worst  share
 ──────────────┼────────────────────┼────────────────────┼────────────────────
 512      24   │   6        6       │   6        7       │      13         54 %
 1024     28   │   7        9       │   6       10       │      19         68 %
 2048     32   │   7       11       │  10       12       │      23         72 %
```

**Why "fwd+bwd" matters.** A classic attack starts in the middle of the
permutation and works both ways ("inside-out"). If the forward part and the
backward part each stay incomplete for some rounds, those rounds add up.
The column "share" says how much of the cipher such a start already covers
with diffusion alone, before any clever trick.

**Why the backward direction is slower for 2048.** The sweep runs left to
right. Going forward, a change at the left end travels across all chunks in
ONE sweep. Going backward, the sweep runs right to left with the inverse
box, and the lane-swap bottleneck (4.1) is at its thinnest: 1 of 16 chunks.

Avalanche at the cipher's own start (each output bit flips with chance near
0.5; 256 samples per cell, outliers beyond 5 standard deviations counted):

```
 width  forward: first round with no outliers   backward
 512    8                                       6
 1024   7                                       6
 2048   7                                       10
```

---

## ╭⟢ 6 Differential trails 🧵

**Def. 8 — difference.** The xor of two inputs. **Def. 9 — trail.** A
predicted path of differences through each round. **Def. 10 — weight.**
`-log2(probability)` of the trail; weight 12 means 1 in 4096 pairs follow it.

**Method.** Exact probabilities per bit column of the box (all 8 input
patterns enumerated, including the coupling between the AND/OR gates that
share an input bit), then greedy: in every box, keep the most likely output
difference. Starting points: every single input bit, at every round of the
schedule.

**The model was checked against reality** with 4 194 304 real pairs:

```
   rounds   predicted weight   measured weight
   1        0.00               0.00
   2        2.00               2.00
   3        12.00              12.01
```

**Calibration.** The same search on the original Gimli-384:

```
 rounds │ NuGimli-512  NuGimli-1024  NuGimli-2048 │ Gimli-384 (same search)
 ───────┼─────────────────────────────────────────┼────────────────────────
   1    │      0             0             0      │     0
   2    │      2             2             2      │     2
   3    │     12            10            10      │     6
   4    │     37            47            47      │    12
   5    │     90           220           499      │    26
   6    │    204           504          1196      │    52
   7    │    432          1055          2232      │   100
   8    │    768          1815             -      │   168
```

The Gimli designers report a best 8-round trail of weight about 52, while
the greedy search finds 168. So greedy is roughly **3x too pessimistic**
for the attacker at 8 rounds. A real search (MILP or SAT, as used in the
literature) will beat these numbers.

**Reading.** Per round, NuGimli's trail weight grows much faster than
Gimli's, because every middle chunk passes through 2-3 boxes per round
instead of 1. Even if the true best trails were 4x lighter than the greedy
ones, the 512-bit profile would cross weight 512 within roughly 10-12
rounds, about half of its 24. Differential trails do not look like
the weak point. (◕‿◕✿)

---

## ╭⟢ 7 Zero-sum (integral) distinguishers ⚖️

**Def. 11 — cube.** Pick `d` input bits and try all `2^d` settings of them,
while all other bits stay fixed. **Def. 12 — zero-sum.** An output bit
whose xor over the whole cube is 0. A random function gives a zero-sum on a
given bit half the time; repeated over 12 random fixed parts, only 1 in
4096 bits passes by chance. A bit that passes all 12 shows structure.

Rounds for which some tested cube still leaves balanced bits (isolated
1-3 hits at later rounds are the expected chance hits and are ignored):

```
 width │ forward (d=16)        │ backward (d=16)         │ inside-out estimate
 ──────┼───────────────────────┼─────────────────────────┼────────────────────
 512   │ 7  (d=20: 7, 8 weak)  │ 5  (256 bits at r5)     │ 12 of 24
 1024  │ 6  (384 bits at r6)   │ 5  (512 bits at r5)     │ 11 of 28
 2048  │ 6  (384 bits at r6)   │ 9  (128-192 bits at r9) │ 15 of 32
```

For 2048 backward, already `d = 8` (256 inputs) leaves 128 bits balanced
after 9 inverse rounds. That is not low algebraic degree. Those output bits
simply do not yet depend on the cube bits: the slow backward diffusion of
chapter 5 again.

The inside-out column adds both directions and is indicative only. A real
attack must fit both halves around one middle structure. Published tools
(division property, MILP) usually reach clearly further than plain cubes.

---

## ╭⟢ 8 The key layer (Even-Mansour) 🔑

```
          K                 K
          │                 │
   X ──► xor ──► P ──────► xor ──► C
```

### 8.1 Generic security

For one key on both sides, Dunkelman, Keller and Shamir (EUROCRYPT 2012,
"Minimalism in cryptography") show a key-recovery trade-off of
`data x time ≈ 2^n` for an `n`-bit block. For 512 bits that is far out of
reach (for example 2^256 data and 2^256 time). This bound ASSUMES that P
behaves like a random permutation, which is exactly what is unproven here.

### 8.2 The built-in related-key relation ⚠

For every difference `D`:

```
   E(X xor D, K xor D) = K xor D xor P(X xor D xor K xor D)
                       = K xor D xor P(X xor K)
                       = E(X, K) xor D
```

This holds with probability 1 for every Even-Mansour cipher, so it is not
a flaw of P. It means one thing in practice: **never build keys by xoring
something into a master key** (counters, labels, session numbers). Use
`deriveCascade*`. The repo's related-key search flipped key bits with the
block held fixed, so it could not see this relation and reported zero.
That is now pinned in `test_nugimli` and stated in the report (13.2).

### 8.3 No mode

`cascadeEncrypt*` encrypts ONE block, deterministically: the same block and
key always give the same output. There is no nonce, no chaining and no
integrity check. Using it on several blocks of real data would be "ECB"
(identical blocks show as identical output).

---

## ╭⟢ 9 Width transitions (SHAKE256 derivation) 🔀

```
 prefix bytes (all public), then the secret source:
 ┌─────────────────────────┬─────┬─────┬─────────┬─────────┬─────────┬─────────┬──────────┬─────┬─────────┬────────┐
 │ "Tyr-NuGimli-Cascade-KDF│ ver │ pur │ srcBits │ dstBits │ outLen  │ tagLen  │ ctxLen   │ tag │ context │ source │
 │  (23 bytes)             │ 1 B │ 1 B │ u32 LE  │ u32 LE  │ u32 LE  │ u32 LE  │ u64 LE   │     │         │        │
 └─────────────────────────┴─────┴─────┴─────────┴─────────┴─────────┴─────────┴──────────┴─────┴─────────┴────────┘
   pur: 1 = state, 2 = key        output: SHAKE256(prefix || source), dstBits/8 bytes
```

- **Injective:** every length comes before its field, and the magic text has
  fixed length. Two different domains can never produce the same SHAKE
  input. ✔
- **State and key separated** by the purpose byte. ✔
- **Bad sizes refused** (source length must match its declared width; tag
  1..255 bytes; context up to 65 535 bytes). ✔
- **Security ceiling.** SHAKE256 gives at most 256-bit security. A 2048-bit
  "key" made this way is still a 256-bit secret, spread out. 256 bits is
  plenty, but the width is not extra strength.
- **README pattern** `cascadeEncrypt(target.state, target.key)` encrypts
  one derived value with another derived value from the same SHAKE call.
  The result is a fixed function of the source, so it cannot be stronger
  than SHAKE256 output of the same length. Use it to test the API, not as
  added protection.

---

## ╭⟢ 10 Side channels and memory 🕯️

- No table lookups and no branches on secret data. All loop bounds,
  rotations, swap targets and constants depend only on the public round
  number. The inverse box runs a fixed 32 passes. ✔
- The repo's Welch timing tests (`evaluate_nugimli_leakage`) passed on the
  measuring machine. That is evidence for one compiler and one CPU, not a
  proof.
- Derived material and temporary byte buffers are wiped with volatile
  stores. ✔
- The SHAKE256 sponge state (which held the secret source) is wiped after
  squeezing, together with the last input block and the squeeze copy. This
  was missing library-wide and was fixed for every SHA3/SHAKE call
  (commit a11a551; cost on SHAKE256 at most 2 %). ✔
- `encrypt`/`decrypt` return copies; intermediate states are not wiped
  (normal for Nim value semantics; mention in threat models that need it).

---

## ╭⟢ 11 Speed 🐎

AVX2 build, measured while other jobs ran on the machine, so the values are
approximate:

```
 width   forward ns/byte   inverse ns/byte   inverse / forward
 512     7.9               57                7.3x
 1024    10.8              95                8.8x
 2048    12.7              124               9.8x
 SHAKE256 (same build)  1.7 ns/byte
```

NuGimli is several times slower than SHAKE256 here. Part of that is
avoidable: the SIMD box loads and stores each chunk through a temporary
array, and `swapChunkBlocks` re-checks its bounds in every round although
all positions are fixed at compile time.

---

## ╭⟢ 12 What the repo's own evidence can and cannot show

```
 tool                         what it measures                 limit
 ───────────────────────────  ───────────────────────────────  ───────────────────────────────
 evaluate_nugimli             avalanche, stream statistics     FULL rounds only: a 6-round
                              on full rounds                   version passes these as well
 evaluate_nugimli (diffusion) 3 input positions per width      too few to find slow spots
 evaluate_nugimli_streams     NIST-style statistics            cannot see structure
 evaluate_nugimli_advanced    GF(2) rank, rotations, slides,   bounded black-box searches on
                              sampled linear/differential,     full rounds; related-key part
                              small cubes                      was blind to 8.2 (fixed)
 evaluate_nugimli_leakage     timing                           good, as far as timing goes
```

**How security is judged in the field.** Nobody shows that the full cipher
"passes tests"; every serious cipher does. Instead one asks how many rounds
the best known attack breaks, and how many rounds remain as reserve. AES
has 10 rounds with the best single-key attacks at about 7. Keccak has 24
with practical collision attacks at about 5-6. That needs reduced-round results,
which is why this review measures rounds 1, 2, 3, ... and not only the
full count.

---

## ╭⟢ 13 Findings and fixes 🛠️

```
 #  severity   finding                                          status
 ── ─────────  ───────────────────────────────────────────────  ──────────────────────
 1  bug        `import tyr` no longer reached NuGimli (public   FIXED: restored
               surface lost in 52ae317); README example did     src/tyr/ciphers/nugimli.nim,
               not compile                                      exported from ciphers.nim
 2  evidence   related-key search blind to E(X^D,K^D)=E(X,K)^D  FIXED: test pins it;
               and reported 0                                   report states it
 3  design     cross-lane mixing: 1 chunk per even round        FIXED: revision 2, every
               (6.25 % at 2048)                                 even chunk (14.1)
 4  design     round count grows slower than diffusion needs    FIXED by row 3: now
               (fwd+bwd worst = 54 / 68 / 72 % of the rounds)   50 / 39 / 34 %
 5  design     lane-swap target is always an even chunk         FIXED by row 3: by design
 6  claim      "security" of 2048-bit derived material is       documented here
               capped at 256 bits by SHAKE256
 7  hygiene    SHAKE256 sponge state not wiped                  FIXED library-wide (a11a551)
 8  speed      inverse 7-10x slower; per-round bound checks     OPEN (minor)
               in swapChunkBlocks; width checks at run time
               although the width is fixed at compile time
```

---

## ╭⟢ 14 Recommendations 🧭

1. **Keep it experimental.** No real data until an outside cryptanalyst
   has looked at it. Point them at chapters 4 and 5 first.
2. **Fix the lane bottleneck before adding rounds.** DONE (revision 2,
   2026-10-11): every even chunk now swaps its lanes. The wide profiles
   went past the 512-bit level, so the round counts stay 24 / 28 / 32.
   Swapping EVERY chunk does nothing at all (see 14.1) - never use it.
   (With revision 1, keeping the 512-bit ratio would have needed about
   35 rounds for 1024 and 43 for 2048.)
3. **Decide what it is for.** For "turn a 1024-bit secret into an
   independent 2048-bit one", SHAKE256 alone already does this with a
   standard security argument. A new permutation earns its place only
   inside a mode with a stated goal (for example a sponge or a wide-block
   cipher with a nonce), and that mode needs its own bound.
4. **Get real bounds.** Use MILP/SAT trail search for differential and
   linear trails, and the division property for integral attacks, on
   reduced rounds. Compare with the published Gimli results using the
   same tools.
5. **Small clean-ups:** make width checks
   compile-time errors; remove run-time bound checks from the hot loop.

### 14.1 The lane-swap fix, measured

Step 2 of a round (the lane swap) is the only step that moves a bit to
another lane. Three choices of WHICH chunks get it were measured with
`nimble evaluate_nugimli_rounds` (all other steps unchanged):

```
 lane mix            bits  fwd+bwd worst   lane reach   zero-sum      greedy trail
                           full diffusion  fwd / bwd    fwd / bwd     at 6 rounds
 ──────────────────  ────  ──────────────  ───────────  ────────────  ────────────
 one chunk (rev. 1)   512  13/24  (54 %)     5 / 6       7 / 5          204
                     1024  19/28  (68 %)     7 / 8       6 / 5          504
                     2048  23/32  (72 %)     8 / 10      6 / 9         1196
 every even chunk     512  12/24  (50 %)     4 / 6       6 / 5          229  <- rev. 2
                     1024  11/28  (39 %)     4 / 6       6 / 5          750
                     2048  11/32  (34 %)     4 / 6       6 / 5         1994
 every chunk          512  not reached       >12 / >12   >12 / >12      152
 (control)           1024  not reached       >12 / >12   >12 / >12      487
                     2048  not reached       >12 / >12   >12 / >12     1178
```

(lower is better in every column except the trail weight)

What it shows:

- **Every even chunk** removes the width penalty. The wide profiles now
  need FEWER rounds than the 512-bit one, so their reserve grows with
  width instead of shrinking. The weak 2048-bit backward zero-sum (9
  rounds) drops to 5. Cost: a few extra word swaps on even rounds, small
  next to the boxes.
- **Every chunk** is a trap (ꐦ°᷄д°᷅): a swap applied the same way to every
  chunk only renames the columns. Boxes, twist and butterfly all work
  column by column, so no bit ever meets another lane. Gimli itself swaps
  only one row for exactly this reason. Kept in the tool as a control.

"Every even chunk" is in `src/` since 2026-10-11 (revision 2). Every
output changed, so `evaluation/tests/nugimli_cascade_vectors.nim` and the
frozen fingerprints in `test_nugimli.nim` were made anew. They were taken
from the direct reference loops and checked against the optimized code and
against the independent model (`nimble test_nugimli_model`): all three agree.

Speed of one full permutation, before and after (median of 15 runs):

```
 bits   revision 1   revision 2   cost
 ────   ──────────   ──────────   ──────
  512    1015-1060    1074-1076   +1-6 %
 1024    3160-3180    3270-3282   +3-4 %
 2048    8184-8228    8451-8475   +3 %
        (nanoseconds)
```

No old copy is kept: the cipher is experimental, nothing may depend on
its outputs, and keeping two designs would only invite mixing them up.

---

## ╭⟢ 15 How the numbers were made 🧪

All measurements come from an independent Nim model written for this
review (not the repo code), cross-checked against the repo code and the
vectors (chapter 3). Seeds were fixed; every run is deterministic.

```
 method  what                                             cost / sample size
 ──────  ───────────────────────────────────────────────  ───────────────────────────────
 A       model vs vectors vs repo (both backends)         200 random states per width
 B       avalanche at own start, both directions          all (512) / every 2nd / every 4th
                                                          input bit x 256 states
 C       full diffusion over every window start           128 input bits x 64 states
 D       lane reach (all 4 lanes touched)                 every input bit x 6 states
 E       greedy trails, exact per-column probabilities    every input bit x every start round
 F       trail model vs real pairs                        2^22 pairs per round count
 G       cubes d = 8 / 16 / 20, six position patterns     12 random fixed parts each
 H       lane-symmetric starts                            2000 states per symmetry
```

The tools now live in the repository (methods C-H; A is covered by the
tests, B by the own-start columns):

```
 command                                   what it does
 ────────────────────────────────────────  ──────────────────────────────────────
 nimble test_nugimli_model                 model == src/ at every width, both
                                           inverses agree, every variant invertible
 nimble evaluate_nugimli_rounds            all widths x all lane mixes, ~30 s,
                                           writes build/nugimli_rounds.md
 nimble evaluate_nugimli_rounds_shipped    the shipped design only
```

```
 file (evaluation/nugimli_analysis/)  part
 ───────────────────────────────────  ──────────────────────────────────────
 round_model.nim                      independent model + LaneMix switch
 reduced_rounds.nim                   diffusion, lane reach, zero-sums,
                                      symmetry
 trails.nim                           greedy trails, Gimli calibration,
                                      check on real pairs
```

The repo tool uses cubes of d = 8 and 12 with 20 random fixed parts each
(a bit survives 20 parts by chance with 2^-20, so chance survivors stay
below 0.01 even at 2048 bits). After ANY change to the round function,
run `test_nugimli_model` first: if the model no longer equals `src/`,
every number in the report is about the wrong cipher.
