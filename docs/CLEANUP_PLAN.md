# Tyr-Crypto Cleanup Plan

Written 2026-08-11. Baseline: `nim check src/tyr_crypto.nim` passes with one
warning (unused import in `kyber/poly.nim`). 192 `.nim` files, 50,692 lines.

## Status

```
 Step  What                              State
 ----  --------------------------------  -----------------------------
  1    drop 2 forwarding files           DONE  (commit b22f1f4)
  2    collapse the 32 facade files      DONE  (commit b22f1f4)
  -    compile-time cipher selection     DONE  (commit e29dfbd)
  -    poisoned nimcache / cleanbuild    DONE  (commit e29dfbd)
  -    four call tiers per module        DONE  (commit 52ae317)
  -    folder per algorithm + surface    DONE  (commit dc42cb6)
  -    split basic_api into 5 material   DONE  (this commit)
  -    public names to their own module  DONE  (this commit)
  3    stale test artifacts              PART  build/ cleared; orphan
                                               tests still unwired
  4    merge zeroization helpers         TODO
  5    module-level `## Reference:`      TODO
  6    macro for material's 3 lists      TODO
  7    move rsa/ecdsa_p256/bigint        DONE  (commit 52ae317)
```

`basic_api.nim` is gone. It was 1,857 lines covering every module at once;
it is now five `material.nim` files, one per module, over a shared
`helpers/material.nim`. Step 6 still applies, to what is now
`kems/material.nim`.

Chapter 2 below recorded a recommendation to KEEP the facade layer. That
recommendation was overruled and the layer is gone. The reasoning is kept
because the correction it received is the useful part; see "Decision taken".

---

╭⟢ Chapter 0 — What we found first 🌊

The repo's **outer shell is already production-grade**. These were checked and
need no work:

```
 licensing (UNLICENSE + THIRD_PARTY_LICENSES.md)   OK
 submodules (9, all proper git URLs)               OK
 .gitignore (no binaries/artifacts tracked)        OK
 tracked file count = 532 (nothing stray)          OK
 no user-specific paths in tracked files           OK
 docs/ folder, .iron/ folder, CONTRIBUTING.md      OK
 nimble tasks (test/build/autopush/switch)         OK
```

The problems are **inside the source layout**, not around it.

---

╭⟢ Chapter 1 — The single most important finding ⚠️

**The thing that looks like duplication is the public API. Do not delete it.**

`src/protocols/custom_crypto/*.nim` holds 32 small files that call themselves
"compatibility facade". Ten of them define procs with a `Tyr` in the middle of
the name, like this:

```nim
# custom_crypto/blake3.nim
proc blake3TyrHash*(input: openArray[byte], outLen: int = 32): seq[byte] =
  ## Tyr-suffixed alias for the local BLAKE3 hash.
  result = blake3Hash(input, outLen)
```

Inside Tyr, nothing calls `blake3TyrHash`. That makes it look like dead weight.
It is not. Counting callers **outside** Tyr:

```
 name                 downstream files calling it
 -------------------  ---------------------------
 blake3TyrHash                 16
 shake256Tyr                   16
 blake3TyrKeyedHash            13
 sha3TyrHash                   11
 argon2idTyrHash               11
 gimliTyrXof                   11
 chacha20TyrXor                10
 gimliTyrTag                   10
 gimliTyrStreamXor             10
 poly1305TyrTag                10
 xchacha20TyrXor               10
 aesCtrTyrXor                  10
 shake128Tyr                   10
 ... (all 20 aliases are used, 5-16 files each)
```

Nine repos depend on them: Bifrost-ExchangeProtocols, Eris-Messenger,
Geist-Database, Excalibur-2FA, Heimdall-InteropAuth, Delta-KeyAuthority,
Avalon-PWManager, Torii-Webserver, Cerberus-Firewall.

Those repos also import the facade **paths** directly — about 60 import lines
such as `import protocols/custom_crypto/blake3`, not just `import tyr_crypto`.

**Def. 1 — "the seam".** Tyr uses two names for one function. The internal
name (`blake3Hash`) is what the implementation calls itself. The public name
(`blake3TyrHash`) is what other repos call. The facade file is where one is
translated into the other.

The seam is a real, useful thing: it lets a caller mix Tyr's own BLAKE3 with a
library BLAKE3 in the same file without a name collision. The problem is only
that the seam is **undocumented, inconsistently applied, and mislabelled**.

---

╭⟢ Chapter 2 — Answer to "should the exporters be one file?" 🍣

> **SUPERSEDED — see "Decision taken" at the end of this chapter.**
> The answer below was wrong. It is kept because the mistake is instructive.

Short answer: **no — keep one file per algorithm, but fix what they say.**

Three reasons, strongest first.

**Reason 1 — collapsing them breaks nine repos.**
About 60 import lines across the workspace point at
`protocols/custom_crypto/<name>`. Folding those into `tyr_crypto.nim` deletes
every one of those paths.

**Reason 2 — a granular import is a smaller build.**
Measured on this machine, `-d:danger`:

```
 import protocols/custom_crypto/blake3   ->  1.41 s,  88 KiB,  7 C files
 import tyr_crypto                       ->  2.00 s,  92 KiB, 16 C files
```

The gap is small by default because the PQ backends are `when`-gated. With
liboqs/OpenSSL enabled the gap widens. This reason is real but modest — it
supports the decision, it does not carry it on its own.

**Reason 3 — the file is the natural home for the seam.**
`blake3.nim` is where "internal name → public name" is written down. Merged
into one 400-line `tyr_crypto.nim`, that mapping becomes a wall of aliases with
no structure.

**What should change instead:**

- The header comment says "compatibility facade". That word means *legacy, will
  be removed*. It is wrong — these are the supported public entry points.
  Retitle every one to `<name> <- public surface`.
- 21 of the 32 are pure `import X; export X` with nothing added, while 10 add
  aliases. A reader cannot tell which is which without opening the file.
  Make the rule explicit and uniform (Chapter 3, Step 2).
- `tyr_crypto.nim` importing 28 facades that each import one real module is a
  double hop. That part *can* be flattened without touching public paths.

### Decision taken ✅

The recommendation above was rejected, and rightly. The rule that replaced it:

> **Caller count never justifies a layer.** Bloat and duplicate layers are not
> excused by "other repos import it". Break them, and relink afterwards
> against the right facade.

Two things were wrong in the reasoning above:

1. **Reason 1 was not an argument, it was inertia.** "Nine repos import these
   paths" describes the cost of the fix, not the value of the thing. Sixty
   import lines are a morning's work; a permanent extra hop is forever.

2. **Reason 2 was doing the compiler's job by hand.** Nim already drops what
   a program does not use, and `when` already gates what gets compiled. A
   hand-built layer of 32 files to influence build size duplicates a job the
   toolchain already does. Where a genuine compile-time choice IS wanted, it
   belongs in one `when` wrapper — which is what `protocols/ciphers.nim` now
   is — not in 32 files that exist all the time.

There is also an architectural reason the caller count was misleading. The
intended shape of the workspace is:

```
   Bifrost ──┐                    Bifrost  -> Tyr, for message encryption
             ├──> Tyr             Geist    -> Tyr, for at-rest encryption
   Geist ────┘                    everyone else -> Geist, not Tyr

   every other repo ──> Geist ──> Tyr
```

Only Bifrost and Geist should reach Tyr directly. The nine repos counted
above are not nine permanent consumers; most are links that should be routed
through Geist anyway. Preserving their paths would have frozen a wiring
diagram that is itself being replaced.

**What was actually done:**

- all 32 facade files deleted
- each PQ family's `operations` module re-exports its `params` (and `types`
  for BIKE), so one import is self-sufficient and no facade is needed
- the 20 public `...Tyr...` names now live in exactly one file,
  `src/protocols/public_names.nim`
- 144 import statements across 66 files repointed at the real modules

Downstream repos must relink against `tyr_crypto` or the real module path.
That breakage is intended.

---

╭⟢ Chapter 3 — The work, in order of risk 🐦‍🔥

Each step is independent. Steps 1–3 cannot break a downstream repo. Steps 4–6
change internals only. Step 7 is the one that needs a decision.

### Step 1 — Delete the second forwarding layer  *(no risk)*

Two files exist only to forward to a file one directory up:

```
 src/protocols/wrapper/algorithms.nim   (6 lines) -> ../algorithms
 src/protocols/wrapper/suite_api.nim    (6 lines) -> ../suite_api
```

Nothing outside the repo imports them. Only six in-repo tests do:
`test_xchacha20_gimli`, `test_xchacha20_aes_gimli_poly1305`, `test_wrapper`,
`test_xchacha20_aes_gimli`, `test_aes_gimli`, `test_pin_key`.

Repoint those six tests at `src/protocols/algorithms` and
`src/protocols/suite_api`, then delete the two files.

This also fixes a genuine reading trap: there are currently **three** files
named `algorithms.nim`, and two of them are unrelated.

```
 src/protocols/algorithms.nim              -> CipherSuite / AuthType enums
 src/protocols/wrapper/algorithms.nim      -> forwards to the above  (DELETE)
 src/protocols/wrapper/helpers/algorithms.nim -> KyberTier etc. (different!)
```

After the delete, two remain with genuinely different content. Rename
`wrapper/helpers/algorithms.nim` to `wrapper/helpers/tiers.nim` so the names
stop lying.

### Step 2 — Make the seam explicit and uniform  *(no risk)*

Write the rule down once, in `docs/CODE_LAYOUT.md`:

```
 internal name  blake3Hash        <- what the implementation calls itself
 public name    blake3TyrHash     <- what other repos call
                                     "Tyr" marks "this repo's own version",
                                     so callers can hold two BLAKE3s at once
```

Then apply it consistently. Right now `x25519` and `ed25519` define the public
`Tyr` name down in the implementation file, while `blake3` and `sha3` define it
up in the facade. Same idea, two different places. Pick the facade for all of
them, so there is exactly one place to look.

Retitle all 32 headers from "compatibility facade" to "public surface".

### Step 3 — Sweep stale build artifacts  *(no risk)*

Six `.exe` files in `tests/` have no matching `.nim` — leftovers from deleted
tests. They are gitignored, so this is disk hygiene only:

```
 test_basic_api.exe          test_dispatch_api.exe
 test_dna_transcriber.exe    test_material_api.exe
 test_sigma_perf_dilithium_avx2.exe
 test_sigma_perf_dilithium_scalar.exe
```

`test_dna_transcriber.exe` is not from this project at all.

Ten test `.nim` files are not referenced by any nimble task or the parallel
runner, so they never run in CI: `test_all`, `test_certificate_codecs`,
`test_falcon_tyr_android_smoke`, `test_falcon_tyr_simd_smoke`,
`test_otter_catalog`, `test_otter_perf_blake3_chacha`,
`test_otter_perf_dilithium`, `test_otter_perf_x25519`,
`test_sigma_perf_blake3_chacha_compare`, `test_tls_primitives`.

Decide per file: wire into a task, or delete. `test_certificate_codecs` and
`test_tls_primitives` cover shipped code and should be wired in, not deleted.

### Step 4 — Consolidate the zeroization helpers  *(low risk, crypto-sensitive)*

The same two helpers are written out eight times:

```
 module                                       has
 -------------------------------------------  ------------------------------
 custom_crypto/symmetric/secure_memory.nim    secureClearBytes, secureClearPod
 asymmetric/pq/kyber/util.nim                 + clearBytes, secureZeroMem, clearPod
 asymmetric/pq/falcon/util.nim                + clearSeqData, secureClearSeqData
 asymmetric/pq/frodo/util.nim                 clearBytes, secureClearBytes
 asymmetric/pq/sphincs/util.nim               clearBytes
 asymmetric/pq/dilithium/poly.nim             clearBytes
 asymmetric/pq/common/pq_rng.nim              secureClearBytes x2
 asymmetric/none_pq/x25519_common.nim         secureZeroMem, secureClearPod, secureClearBytes
 bindings/pqclean_common.nim                  secureClearBytes x2
```

They were compared and are semantically identical. The two-way split is
deliberate and must be preserved exactly:

```
 clearBytes / clearPod        -> zeroMem       -> fast, for PUBLIC scratch
 secureClearBytes / ...Pod    -> volatileStore -> for SECRETS, survives the
                                                  optimiser deleting the write
```

Move the full set into `custom_crypto/symmetric/secure_memory.nim` (already the
best-documented copy), covering `openArray`, `seq`, and `static array`
overloads. Have the other eight modules import it.

Two cautions:
- `falcon/util.nim` sits under `{.push boundChecks: off.}`. Check the shared
  version does not silently re-enable bounds checks in Falcon's hot path.
- Do this step alone, with `nimble test_all` before and after. Zeroization
  bugs are invisible in normal tests.

### Step 5 — Collapse the `## Reference:` boilerplate  *(low risk, big readability win)*

There are **1,163** of these lines, averaging 244 characters — about 284 KB of
comment text. Example, on a five-line byte-clearing helper:

```nim
## Reference: [KYBER-R3-20210804] version 3.02 sections 1.3 and 4, algorithms
## 1-9; canonical byte and polynomial encoding rules for `clearBytes`;
## pitfall: preserve the cited equations, fixed bounds, and representation
## invariants.
proc clearBytes*(S: var seq[byte]) =
  if S.len == 0: return
  zeroMem(addr S[0], S.len)
```

`clearBytes` has nothing to do with Kyber's polynomial encoding rules. The line
is wrong on its face.

It is wrong because it is **generated**, not written. `tools/check_asymmetric_
references.nim` builds each line purely from the file's name via its
`modulePart()` lookup, then splices in the proc name. Proof that it carries no
per-proc information:

```
 distinct spec ids across all 1,163 lines   12
 distinct "pitfall:" endings                10
 both chosen from the FILE PATH alone, never from the function
```

So 1,163 lines encode what the file path already says.

**Fix:** emit one reference block per *module* (in the file header, where the
rule actually applies), not one per declaration. Update
`check_asymmetric_references.nim` to verify the module header instead. That is
~60 header blocks replacing 1,163 inline lines, with zero citation coverage
lost — every function in the file is still governed by its file's header.

Keep per-proc citations only where a function implements a *specific* named
algorithm step and the header would be too coarse. Expect a handful, not a
thousand.

### Step 6 — Collapse the three parallel lists in `kems/material.nim`  *(medium risk)*

`kems/material.nim` is 942 lines after the split. Most of it is fine — it is a
dispatch table and it reads well. But adding one algorithm today means editing
**three separate lists that must stay in sync**:

```
 line ~174   type   blake3HashM* = object            <- marker type
 line ~560   buildLayout(akBlake3Hash, okHash, 32, ...)  <- size table
 line ~669   proc algorithmOf*(T: typedesc[blake3HashM]): AlgorithmKind = akBlake3Hash
```

The third list is 96 one-line procs that do nothing but map list 1 to list 2.

A single `declareAlgorithm` macro taking the marker name, the kind, the
operation, the output size and the slots can emit all three. That removes ~96
lines and, more importantly, removes the chance of the three drifting apart.

Do this **after** Steps 1–5, and only with `test_dispatch_api` /
`test_primitives_api` / `test_quick_api` green, since a macro error here fails
at compile time in every consumer.

### Step 7 — Move the four misplaced implementations  *(needs your decision)*

Every algorithm lives under `symmetric/` or `asymmetric/`, except four real
implementations sitting loose at the top of `custom_crypto/`:

```
 rsa.nim          697 lines
 ecdsa_p256.nim   539 lines
 bigint.nim       505 lines
 nugimli.nim       20 lines  (a facade; the impl is in nugimli/, this is fine)
```

`rsa` and `ecdsa_p256` belong in `asymmetric/none_pq/`. `bigint` is shared
maths, so `custom_crypto/math/` or Fylgia-Utils.

**This is the one step that breaks downstream paths.** `Geist-Database` imports
`protocols/custom_crypto/rsa` and `protocols/custom_crypto/ecdsa_p256`
directly. Options:

- (a) Move the implementation, leave a one-line re-export at the old path.
  Nothing breaks. Costs three tiny files.
- (b) Move and fix the downstream imports in the same pass. Cleaner tree, needs
  a coordinated commit across two repos.

Recommend **(a)** — it matches how the other 32 files already work.

---

╭⟢ Chapter 4 — Things deliberately NOT changed 🍥

- **The `Tyr` alias layer.** Load-bearing public API (Chapter 1).
- **The 96-entry `buildLayout` table.** It is long, but it is a declarative
  data table. Long is correct here.
- **`let` usage.** 334 bare `let` declarations exist against the "no let"
  convention, 100 of them in `falcon/keygen.nim`. That file is a transcription
  of the Falcon reference implementation. Rewriting it to match house style
  risks silent cryptographic breakage for a style win. Leave it; note the
  exemption in `docs/CODE_LAYOUT.md` instead.
- **Deep nesting.** 447 lines at 5+ indent levels, nearly all in PQ maths
  kernels where the loop structure mirrors the published algorithm. Same
  reasoning.

Chapter 4 is the "not to delete important stuff" half of the request. The
conventions are a tool for readability; in transcribed reference cryptography,
matching the published pseudocode *is* the readability.

---

╭⟢ Chapter 5 — Suggested order and expected effect 🌸

```
 Step  What                          Risk    Lines removed   Breaks anything?
 ----  ----------------------------  ------  --------------  ----------------
  1    drop 2 forwarding files          -            ~12     no (6 tests edited)
  2    document + unify the seam        -             ~0     no
  3    sweep stale test artifacts       -             ~0     no
  4    merge zeroization helpers       low          ~120     no
  5    module-level citations          low        ~1,100     no
  6    macro for the 3 lists           med           ~150     no (compile-checked)
  7    move rsa/ecdsa/bigint           med             ~0     no, if (a)
                                              --------------
                                               ~1,380 lines
```

Roughly 1,380 lines out of 50,692 — under 3% by count, but concentrated
entirely in the parts a maintainer reads first: module headers, the public
surface, and the dispatch table.

Run `nimble check_core` after every step and `nimble test_all` after Steps 4,
6 and 7.
