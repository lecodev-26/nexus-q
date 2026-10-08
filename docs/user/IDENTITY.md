# Identity Guide

NEXUS-Q identities provide a lifecycle around signing keys and signed credentials.

## Create an identity

```bash
nexusq identity create ./example.nqv --label alice
```

List identities:

```bash
nexusq identity list ./example.nqv
```

## Sign and verify

A signature operation references an identity:

```bash
nexusq sign sign ./example.nqv --identity <identity-id> document.txt
```

Verification uses the same identity and the generated signature file:

```bash
nexusq sign verify ./example.nqv --identity <identity-id> document.txt document.sig
```

## Credentials

A credential binds claims to issuer and subject identities:

```bash
nexusq credential issue ./example.nqv --issuer <issuer-id> --subject <subject-id> --claims '{"role":"operator"}' credential.json
```

Verify it with:

```bash
nexusq credential verify ./example.nqv credential.json
```

Keep private identity material inside the vault. Export only public material or explicitly wrapped forms where the API permits it.

## Credential key rotation

Each credential records the exact issuer signing-key identifier and signature algorithm used to sign it. New credentials use ML-DSA-65. Issuer key rotation therefore does not invalidate previously issued credentials merely because the identity now has a newer signing key. The verifier resolves the historical key, rejects revoked/destroyed issuer keys and expired credentials, and supports individual credential revocation persisted by the vault.
