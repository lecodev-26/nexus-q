# Constant-time comparison inventory

This inventory records the secret-sensitive equality and authentication paths
reviewed for Issue #84. It describes the source-level design; it is not a claim
that the generated machine code has been proven constant-time on every compiler,
target, or processor.

## Secret-sensitive paths

| Surface | Implementation | Review result |
| --- | --- | --- |
| HTTP bearer authentication | `crates/nexusq-server/src/main.rs` — `is_bearer_authorized` | Uses `subtle::ConstantTimeEq` on token bytes. The `Bearer ` scheme/prefix parsing is public protocol handling; token contents are not compared with ordinary equality. Slice-comparison work can depend on the supplied length, which is part of the request metadata; the constant-time guarantee concerns contents. |
| Administrative bearer credentials | `crates/nexusq-admin/src/lib.rs` — `AdminStore::authenticate` | Hashes the presented token to a fixed-size SHA-256 digest and compares digest arrays with `ConstantTimeEq`. Subject/role metadata is returned only after the match. |
| EST Basic credentials | `crates/nexusq-enrollment/src/lib.rs` — `EstCredentials::authenticate` | Looks up the public username, hashes the candidate username/password pair, and compares fixed-size digests with `ConstantTimeEq`. Username lookup is not a password comparison. |
| PKI-cluster bearer credentials | `crates/nexusq-pki-cluster/src/lib.rs` — `PkiTenantRegistry::authorize` and `authorized` | Hashes the presented token and compares the fixed-size SHA-256 digest with the configured digest using `ConstantTimeEq`. |
| CMP password-based MAC | `crates/nexusq-enrollment/src/cmpv2.rs` — PBM protection verification | Compares the expected and received MAC with `ConstantTimeEq`; the authentication result is acted on only after the comparison. The received length is public protocol metadata. |
| Administrative audit HMAC | `crates/nexusq-admin/src/lib.rs` — audit-file verification | Compares the stored record MAC with the recomputed MAC using `ConstantTimeEq`. Record sequence and chain metadata are public integrity data. |
| Core audit HMAC and commitments | `crates/nexusq-core/src/storage/audit_log.rs`, `audit_segment.rs`, and `audit_event.rs` | MACs and stored commitments use `ConstantTimeEq`. Hash-chain metadata is integrity data, not an authentication secret; constant-time comparison is retained consistently. |
| Vault and backup key verifiers | `crates/nexusq-core/src/vault/header.rs` and `storage/backup.rs` | Compare fixed-size derived-key verifiers using `ConstantTimeEq`. |
| ML-DSA signing-key equality | `crates/nexusq-ml-dsa/src/signing.rs` | `SigningKey` and `ExpandedSigningKey` compare secret components through `CtEq` and combine the results as `Choice` values. |
| ML-KEM decapsulation-key equality | `crates/nexusq-ml-kem/src/decapsulation_key.rs` | The secret PKE decryption key and implicit-rejection seed are compared through `CtEq`; their `Choice` results are combined before conversion to `bool`. The encapsulation key is public and is compared separately. |

ML-KEM decapsulation itself selects between the candidate and rejection keys
with `ct_select` using the ciphertext re-encryption check. It does not branch on
the validity bit. This source-level property does not replace review of the
cryptographic implementation and its generated code.

## Reviewed ordinary comparisons

The following comparisons were reviewed and are not equality checks on secret
credential material in their current context:

- HSM token labels and serial numbers are public device-identification metadata.
- Certificate public-key bytes, signature/ciphertext lengths, algorithm OIDs,
  public identifiers, and public-key fingerprints are public protocol data.
- ML-KEM public-key encoding checks and ML-DSA verification challenge checks
  operate on public input or public verification data.
- Audit sequence numbers, key epochs, record hashes, and chain links are
  integrity metadata. Secret MACs/verifiers are compared separately with
  constant-time primitives.
- Attestation nonce equality is a comparison of a verifier-issued challenge,
  not a password or long-term credential; its length is public policy/input
  metadata and the bytes are still compared with `ConstantTimeEq`.
- CLI password confirmation compares two values entered by the same local
  interactive user. It is not a remote credential-verification endpoint or an
  externally observable authentication oracle; this is a local UX check, not a
  claim of constant-time password verification.

If any of these values become secret-bearing in a future design, their equality
must be re-reviewed rather than relying on this classification.

## Static enforcement and limitations

The `NEXUSQ_CRYPTO_SECRET_COMPARISON` Dylint rule warns on ordinary `==`/`!=`
expressions and `.eq()`/`.ne()` method calls when source identifiers indicate
secret-bearing values. It includes explicit coverage for seeds, password/token
names, MACs, the ML-KEM `dk_pke` field, and the `DecapsulationKey.z` field. Its
positive and negative fixtures are checked by the lint crate's unit tests, and
the dedicated `NEXUS-Q Dylint Crypto Rules` GitHub Actions workflow runs the
lint over the workspace on relevant pull requests.

This is a source-text heuristic, not taint analysis or full data-flow analysis.
It can miss unfamiliar field names, aliases, helper functions, indirect
comparisons, and secret-dependent branches that do not use equality operators;
it can also flag public values whose names resemble secrets. Every warning
requires human review. A clean lint run does not prove that all secret-dependent
comparisons or branches have been found.

Functional tests can establish that equal and unequal values are accepted or
rejected correctly. They cannot establish constant-time behavior. Timing
assurance requires separate review of generated machine code, compiler and
target behavior, and appropriate platform-specific side-channel analysis.
Neither this inventory, the lint, nor functional tests constitute a proof of
constant-time execution or a certification claim.
