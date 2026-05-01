# NTRU/SABER Research Document License Notes

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

- `2017-0667_high_speed_key_encapsulation_from_ntru.pdf`
- `2018-1018_faster_multiplication_z2m_cortex_m4.pdf`
- `2019-1309_saberx4_high_throughput_software.pdf`
- `2020-0733_saber_side_channel_resistant_implementation.pdf`
- `2020-0992_single_trace_message_encoding_lattice_kems.pdf`
- `2020-1397_ntt_multiplication_ntt_unfriendly_rings.pdf`
- `2021-0079_masked_ind_cca_secure_saber_attack.pdf`
- `2021-0104_attacking_defending_masked_poly_comparison.pdf`
- `2021-0718_generic_sca_cca_attacks_ntru_kems.pdf`
- `2021-0790_side_channel_assisted_attack_on_ntru.pdf`
- `2021-0986_neon_ntt_faster_dilithium_kyber_saber.pdf`
- `2021-1452_lightweight_sca_resistant_saber.pdf`
- `2022-0494_single_trace_omega_small_sampling_ntru.pdf`
- `2022-0919_side_channel_attacks_lattice_kems.pdf`
- `2024-0548_isochronous_fixed_weight_sampling_ntru.pdf`

The TCHES article `2022_tches_verified_ntt_multiplications_ntru_saber.pdf`
is licensed under Creative Commons Attribution 4.0 on the article page.

The NIST technical-series report
`supporting/nist_ir_8413_upd1_pqc_round3_report.pdf` is tracked under the
NIST technical-series publication terms. NIST's notice says NIST-authored
technical-series works are not subject to U.S. copyright protection and grants
worldwide reprint rights where NIST may assert foreign rights. Keep the NIST
attribution and citation when redistributing.

## Ignored Local-Cache Documents

No explicit redistribution license was found in the local PDF text for these
documents during this pass, so they are left on disk locally but are removed
from the git index and ignored:

- `papers/2021_nist_pqc_optimized_armv8_neon_ntru_saber.pdf`
- `papers/2021_pqcrypto_fast_neon_based_multiplication.pdf`
- `supporting/ntru_spec_20190330.pdf`
- `supporting/saber_round3_spec.pdf`

These files are still reproducible from `papers.lock.json` and
`download_papers.ps1`.
