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

## Practical Interpretation For This Repo

- You can treat original Tyr-Crypto code as `Unlicense`.
- You must not assume the entire checked-out submodule tree is uniformly
  MIT-compatible or relicensed by Tyr-Crypto.
- If you redistribute binaries, copied source, or vendor code from these
  submodules, follow the upstream license and notice files that apply to the
  specific component you are shipping.
