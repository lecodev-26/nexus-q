# ADR 0005: Treatment of RUSTSEC-2023-0071 (`rsa`)

- Status: Accepted
- Date: 2026-10-25
- Scope: dependency-audit policy for NEXUS-Q v4.1.2.

## Context and source-level use

`RUSTSEC-2023-0071` concerns timing behavior in RSA private-key decryption. The advisory is present in the dependency-audit policy as an exception. It is not fixed by this ADR. Source review found no direct `rsa` imports or direct use of the `rsa` crate under the project `src/` trees. The transitive path is through `cms` only.

The two direct `cms` use sites are:

- `crates/nexusq-enrollment/src/lib.rs:25`: `use cms::content_info::ContentInfo;` for CMS `ContentInfo` parsing.
- `crates/nexusq-tsa/src/lib.rs:13`: CMS builder/types (`SignedDataBuilder`, `SignerInfoBuilder`, `CertificateChoices`, `IssuerAndSerialNumber`, `EncapsulatedContentInfo`, `SignerIdentifier`) for ML-DSA `SignedData`.

`crates/nexusq-enrollment/src/acme.rs` handles ACME JWKs as public JSON Web Keys: it validates/serializes the JWK and verifies JWS signatures through `josekit`; it does not call RSA private-key decryption APIs from the `rsa` crate. This observation is a source-path assessment, not a proof that every future reachable path is safe.

The dependency declaration is `cms = \"0.3.0-rc.0\"` in `crates/nexusq-enrollment/Cargo.toml` and `cms = { version = \"0.3.0-rc.0\", features = [\"builder\"] }` in `crates/nexusq-tsa/Cargo.toml`. The pre-release version is currently required by the CMS API surface used here, including the builder APIs used to construct ML-DSA SignedData; replacing it with a stable CMS release must wait until a compatible API exists and is verified by tests. The prerelease status remains a dependency risk and is not represented as stable.

## Recorded dependency tree

Command: `cargo tree -i rsa --locked`

```text
rsa v0.10.0-rc.19
└── cms v0.3.0-rc.0
    ├── nexusq-enrollment v4.1.2 (/data/data/com.termux/files/home/nexus-q-readme-review/crates/nexusq-enrollment)
    │   └── nexusq-pki-cluster v4.1.2 (/data/data/com.termux/files/home/nexus-q-readme-review/crates/nexusq-pki-cluster)
    │   [dev-dependencies]
    │   └── nexusq-hsm v4.1.2 (/data/data/com.termux/files/home/nexus-q-readme-review/crates/nexusq-hsm)
    └── nexusq-tsa v4.1.2 (/data/data/com.termux/files/home/nexus-q-readme-review/crates/nexusq-tsa)
```

This output was captured from the proposed v4.1.2 dependency graph. Re-run the command on the exact release commit and retain its full output with release evidence.

## Decision

Accept a narrowly scoped exception while `rsa` is reachable only through `cms`, no applicable upstream fix is recorded in policy, and the source paths above remain accurate. Keep the exception visible in both `.cargo/audit.toml` and `deny.toml`. Do not describe the advisory as fixed, and do not infer absence of timing leakage from the current call paths.

## Risk and migration plan

1. Track upstream `cms` and `rsa` releases and the advisory's remediation status.
2. Evaluate a stable `cms` release or a patched compatible release; first confirm `ContentInfo` and SignedData builder compatibility.
3. Upgrade in a dedicated dependency-only change; regenerate lockfiles and inspect `cargo tree -i rsa --locked`.
4. Run enrollment CMS parsing/validation tests, TSA SignedData tests, KAT/interoperability checks, `cargo test --workspace --locked`, `cargo audit`, and `cargo deny check`.
5. If CMS can remove the vulnerable dependency or a compatible patched release is available, remove the exception from both audit policies in the same reviewed change.
6. If any direct RSA private-key decryption use is introduced, reassess immediately and block release until remediated or separately approved with explicit risk acceptance.

## Reassessment triggers

- An upstream fix or stable compatible CMS release becomes available.
- CMS usage, cryptographic algorithms, or the dependency graph changes.
- A new source path invokes RSA private-key decryption or audit/KAT/external-review evidence challenges the assumptions.

## Release evidence

For each candidate, record exact commit, full `cargo tree -i rsa --locked`, `cargo audit`, `cargo deny check`, and CI/KAT results. This ADR is not an external audit opinion, certification, or guarantee against timing leakage.
