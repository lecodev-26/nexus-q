# ADR 0005: Temporary exception for RUSTSEC-2023-0071 in the CMS dependency tree

- **Status:** Accepted as a temporary, scoped exception; reassessment required on dependency or CMS changes
- **Date:** 2026-10-25
- **Scope:** Dependency policy only. This ADR does not change cryptographic behavior or enable RSA operations.

## Context

The locked dependency graph contains `rsa 0.10.0-rc.19` through `cms 0.3.0-rc.0`, used by `nexusq-enrollment` and `nexusq-tsa`. RustSec advisory [RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071.html) describes the Marvin timing side channel in RSA private-key decryption and currently reports no patched versions. The current dependency is therefore not described as generally safe merely because the application does not intentionally call RSA decryption.

Repository source review at this decision date found the application uses CMS `ContentInfo` parsing in enrollment and CMS `SignedDataBuilder` for ML-DSA-65 timestamp tokens in the TSA. The reviewed application paths do not use the CMS/RSA dependency to decrypt RSA private-key ciphertexts. The dependency is nevertheless present in the production dependency graph, and future use or a transitive behavior change could alter this assessment.

## Decision

Keep the existing `RUSTSEC-2023-0071` exception in both `cargo audit` and `cargo deny` for now, because removing it without replacing or restructuring the CMS dependency would make the configured security gate fail, while the reviewed application paths do not invoke the vulnerable RSA private-key decryption operation. Treat this as a narrow, temporary risk acceptance—not as a claim that the advisory is fixed, that every transitive path is unreachable, or that the software has passed an independent security audit.

No RSA private-key decryption API may be introduced under this exception. Do not add RSA decryption, RSA key transport, or network-reachable RSA private-key processing without a new security review and removal or replacement of this exception.

## Required controls and reassessment triggers

1. Keep the exception visible in both audit configurations and link it to this ADR.
2. Review the dependency tree and CMS call sites whenever `cms`, `rsa`, enrollment, or TSA dependencies change.
3. Reassess immediately if an upstream fix is released, if a non-RSA-CMS alternative becomes viable, or if production code begins using any RSA private-key operation.
4. Prefer removing the dependency/exception or upgrading to a verified fixed release when available; do not treat a version bump alone as proof of remediation.
5. Run `cargo tree -i rsa --locked`, `cargo audit`, `cargo deny check`, and relevant CMS/enrollment/TSA tests during reassessment.

## Evidence checked

- `cargo tree -i rsa --locked` resolved `rsa 0.10.0-rc.19` through `cms 0.3.0-rc.0` into `nexusq-enrollment` and `nexusq-tsa`.
- Source review of `crates/nexusq-enrollment/src/lib.rs` and `crates/nexusq-tsa/src/lib.rs` identified the CMS parsing and ML-DSA SignedData construction paths described above.
- Advisory status: [RustSec RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071.html).
