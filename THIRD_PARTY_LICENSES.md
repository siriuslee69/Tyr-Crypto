# Third-Party License Notes

This file is a repo-maintenance summary of the checked-out submodule trees in
this workspace. It is not legal advice.

## Tyr-Crypto Code

- Original Tyr-Crypto code is released under the `Unlicense`.
- That repo license does not relicense third-party submodules, vendored
  upstream code, or generated native artifacts.

## Top-Level Submodule Licenses Observed Locally

- `submodules/libsodium`
  - top-level license: ISC
- `submodules/liboqs`
  - top-level license: MIT
  - caveat: liboqs includes many per-folder third-party implementations under
    their own license files inside `submodules/liboqs/src`
- `submodules/openssl`
  - top-level license: Apache-2.0

## Additional License Caveats Found In Checked-Out Trees

- The checked-out `submodules/openssl/` tree contains nested helper, provider,
  and test repositories with their own licenses.
- Local inspection found GPL/LGPL materials in nested paths such as:
  - `submodules/openssl/tlsfuzzer`
  - `submodules/openssl/tlslite-ng`
  - `submodules/openssl/pkcs11-provider/tlsfuzzer`
  - `submodules/openssl/pkcs11-provider/tlslite-ng`
- Other nested directories under `submodules/liboqs/` and `submodules/openssl/`
  also carry their own `LICENSE`, `COPYING`, or `NOTICE` files.

## NTRU/SABER Research Documents

- Paper metadata and checksums are recorded in
  `docs/research/ntru_saber/papers.lock.json`.
- Detailed research-document license notes are in
  `docs/research/ntru_saber/LICENSES.md`.
- IACR ePrint papers listed there are treated as `CC-BY-4.0` only when the
  individual ePrint page exposes the CC BY license link.
- The tracked TCHES paper is treated as `CC-BY-4.0` because the article page
  and PDF identify that license.
- The tracked NIST IR 8413 update follows NIST technical-series publication
  terms.
- PDFs without explicit redistribution terms are local cache only, ignored by
  git, and reproducible through `docs/research/ntru_saber/download_papers.ps1`.

## Non-NTRU/SABER PQ Research Documents

- Paper metadata and checksums are recorded in
  `docs/research/pq_non_ntru_saber/papers.lock.json`.
- Detailed research-document license notes are in
  `docs/research/pq_non_ntru_saber/LICENSES.md`.
- IACR ePrint papers listed there are treated as `CC-BY-4.0` or `CC0-1.0`
  according to the individual ePrint page license link.
- Standalone algorithm/specification PDFs without explicit redistribution terms
  are local cache only, ignored by git, and reproducible through
  `docs/research/pq_non_ntru_saber/download_papers.ps1`.

## Practical Interpretation For This Repo

- You can treat original Tyr-Crypto code as `Unlicense`.
- You must not assume the entire checked-out submodule tree is uniformly
  MIT-compatible or relicensed by Tyr-Crypto.
- If you redistribute binaries, copied source, or vendor code from these
  submodules, follow the upstream license and notice files that apply to the
  specific component you are shipping.
