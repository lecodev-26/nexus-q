# ADR 0005: Temporary exception for RUSTSEC-2023-0071 in the CMS dependency tree

- **Status:** Accepted as a temporary, scoped exception; reassessment required on dependency or CMS changes
- **Date:** 2026-10-25
- **Scope:** Dependency policy only. This ADR does not change cryptographic behavior or enable RSA operations.
- **Accountable role:** Maintainer responsible for Rust dependency/security policy; a named individual must be assigned before the next scheduled review.
- **Review status:** Accepted temporarily; no automatic expiry is claimed. Reassess on the triggers below and whenever dependency policy is reviewed.

## Context

The locked dependency graph contains `rsa 0.10.0-rc.19` through `cms 0.3.0-rc.0`, used by `nexusq-enrollment` and `nexusq-tsa`. RustSec advisory [RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071.html) describes the Marvin timing side channel in RSA private-key decryption and currently reports no patched versions. The current dependency is therefore not described as generally safe merely because the application does not intentionally call RSA decryption.

Repository source review at this decision date found the application uses CMS `ContentInfo` parsing in enrollment and CMS `SignedDataBuilder` for ML-DSA-65 timestamp tokens in the TSA. The reviewed application paths do not use the CMS/RSA dependency to decrypt RSA private-key ciphertexts. The dependency is nevertheless present in the production dependency graph, and future use or a transitive behavior change could alter this assessment.

## Reachability analysis (static review; not a formal proof)

### Dependency path

`cargo tree -i rsa --locked` on the reviewed workspace resolves `rsa 0.10.0-rc.19` through `cms 0.3.0-rc.0` into `nexusq-enrollment` and `nexusq-tsa`. The dependency is therefore present in the production dependency graph for those crates; the advisory cannot be dismissed merely because no direct `rsa` import was found in the application.

### Application call sites reviewed

- `crates/nexusq-enrollment/src/lib.rs`: imports `cms::content_info::ContentInfo`; reviewed call sites parse/construct CMS content around lines 864, 924, 977 and 1206. The inspected operations handle certificate/CMS `ContentInfo`; no application call to RSA private-key decryption was found in these call sites.
- `crates/nexusq-tsa/src/lib.rs`: imports `SignedDataBuilder`, `SignerInfoBuilder`, `EncapsulatedContentInfo` and `SignerIdentifier`; builds CMS `SignedData` for RFC 3161 timestamp tokens signed with ML-DSA-65 (around line 334), and parses the resulting `ContentInfo` in tests (around line 536). No RSA private-key decryption operation was found in the reviewed TSA path.
- The application-level paths reviewed are CMS parsing and ML-DSA signature construction/validation, not RSA private-key decryption. The vulnerable Marvin path concerns RSA private-key decryption. This is evidence that the specific application operations reviewed do not intentionally invoke that operation; it is **not** proof that every transitive API is unreachable under all feature sets or malformed inputs.

### Residual uncertainty

The vulnerable dependency is still linked. Static source search does not prove absence of indirect calls inside dependencies, establish timing behavior, or rule out future changes. No dynamic taint/call-graph analysis or independent audit has been performed. Keep the issue disclosed as an accepted dependency risk until the dependency is removed/replaced or an upstream version is independently verified to remediate it.

### Mitigation and migration plan

1. **Immediate:** retain the visible narrow exception; prohibit new RSA private-key decryption/key-transport use; review changes to `cms`, `rsa`, enrollment and TSA; retain negative/positive CMS tests.
2. **Next dependency review:** evaluate whether enrollment can use a parser/representation that does not pull in `cms`/`rsa`, and whether TSA can use a CMS builder with ML-DSA support and no RSA dependency. Prototype behind tests only; do not change production crypto behavior as part of this ADR without separate review.
3. **Upstream path:** track an upstream fixed `rsa` release or a `cms` dependency release that removes the vulnerable path. Verify release notes, source diff, dependency graph and advisory status; a version bump alone is insufficient.
4. **Acceptance test:** run `cargo tree -i rsa --locked`, `cargo tree -e features -i rsa --locked`, `cargo audit`, `cargo deny check`, and enrollment/TSA tests under the selected MSRV. Remove the exception only when the vulnerable dependency is removed or a specific upstream fix is verified and documented.
5. **Owner:** assign a named individual to own the next review and record the date/decision in this ADR before the next release candidate.

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
