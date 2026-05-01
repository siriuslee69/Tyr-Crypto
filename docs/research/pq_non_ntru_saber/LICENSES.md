# Non-NTRU/SABER PQ Research Document License Notes

Date: 2026-05-01

This file is a repo-maintenance summary, not legal advice. The executable
manifest is `papers.lock.json`; use `download_papers.ps1` to restore ignored
local-cache PDFs.

## Policy

Research PDFs are ignored by default. A PDF is whitelisted for tracking only
when the source has explicit redistribution terms. Documents without clear
redistribution terms stay as local cache files, are removed from the git index,
and are recorded in `papers.lock.json` with `gitPolicy:
ignored-local-cache`.

## Tracked Documents With Clear Redistribution Terms

The following ePrint papers have individual ePrint metadata showing `CC BY`
and linking to Creative Commons Attribution 4.0:

- `2016-0659_frodo_take_off_the_ring.pdf`
- `2017-0633_crystals_dilithium.pdf`
- `2017-0634_crystals_kyber.pdf`
- `2018-0039_vectorized_ntt_implementations.pdf`
- `2019-0267_falcon_gaussian_sampling_precision.pdf`
- `2020-0117_bike_constant_time_decoder.pdf`
- `2021-0986_neon_ntt_dilithium_kyber_saber.pdf`
- `2022-0112_kyber_dilithium_speed_memory_cortex_m4.pdf`
- `2022-1726_sphincs_sha_extensions.pdf`
- `2023-0636_multi_armed_sphincs.pdf`
- `2024-0367_accelerating_slh_dsa_hash_unit.pdf`
- `2024-1149_dilithium_sampling_implementation_analysis.pdf`
- `2025-0214_dilithium_rejection_sampling_side_channel.pdf`

The following ePrint papers have individual ePrint metadata showing `CC0`:

- `2023-1962_ntt_multiplication_survey.pdf`
- `2024-0500_side_channel_resistant_sphincs.pdf`

## Ignored Local-Cache Documents

No explicit redistribution license was found in the local PDF text for these
documents during this pass, so they are left on disk locally but are removed
from the git index and ignored:

- `papers/bike_spec_2024_10_10_v5_2.pdf`
- `papers/frodokem_standard_proposal_2025_09_29.pdf`
- `papers/falcon_spec.pdf`
- `papers/classic_mceliece_spec_2022_10_23.pdf`
- `papers/classic_mceliece_implementation_guide_2022_10_23.pdf`

These files are still reproducible from `papers.lock.json` and
`download_papers.ps1`.
