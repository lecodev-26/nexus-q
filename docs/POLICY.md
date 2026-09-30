# Policy engine

The policy engine decides **whether an operation is allowed**. It is
separate from authentication: authentication says who the caller is,
policy says what they may do. The engine lives in the `policy` module
and is consumed by `vault::Session`.

See `docs/SECURITY_MODEL.md` §5.2 for the design rationale.

## Default deny

A session with **no policies attached** allows every operation. This
is the historical behavior and what a fresh vault does.

As soon as a `PolicySet` is attached — **even an empty one** — the
engine turns on and the default becomes **deny**. From that point
every auditable operation must be covered by an explicit allow, or it
is refused.

The distinction is deliberate:

- `policies = None` in the vault body means "the policy engine is not
  in play". This is what old vaults have.
- `policies = Some(set)` means "the engine is in play". Every
  operation goes through it, and `set` decides.

Attaching a set is an explicit decision by the caller:
`session.set_policies(set)`. Clearing it is
`session.clear_policies()`. Both emit a `PolicyChanged` audit event
when auditing is enabled.

## Decision model

The engine is a small, deterministic, fail-closed rule evaluator.

1. Rules are consulted **in order**.
2. A rule **applies** when all of the following hold:
   - the context's operation is in the rule's `operations` list;
   - the rule's `target` matches the context (see "Targets" below);
   - **every** condition in the rule's `conditions` list is satisfied.
3. The **first applying deny wins** and is returned immediately.
4. Applying **allows are remembered**; the first one is returned if
   no deny was seen.
5. If no rule applies, the decision is **NoDecision**. The session
   treats that as a refusal, with the same result as an explicit
   deny.

Two consequences matter:

- A deny at the top of the list cannot be overridden by a later
  allow. That is what makes the engine fail-closed: a guard rule is
  enough to freeze an entire category.
- An allow with no matching deny must be present for any operation
  to succeed.

## Types

### `PolicyOperation`

A closed enum naming the action a rule governs. Examples: `KeyCreate`,
`KeyActivate`, `KeyRotate`, `KeyRevoke`, `KeyDestroy`, `Sign`,
`Encrypt`, `Decrypt`, `KeyAgreement`, `Wrap`, `IdentityCreate`,
`IdentitySign`, `IdentityRotateKey`, `IdentityRevoke`,
`CredentialIssue`, `CredentialVerify`, `EnvelopeSeal`,
`EnvelopeOpen`.

The set is closed: adding an operation requires a new variant and a
new arm in the evaluator, so no rule can silently govern an action
the evaluator does not understand.

### `PolicyTarget`

What a rule applies to:

- `All` — every operation.
- `AnyKey` — operations whose context carries a key.
- `AnyIdentity` — operations whose context carries an identity.
- `Key(id)` — one specific key.
- `Identity(id)` — one specific identity.

`AnyKey` does not match `KeyCreate`, which has no key yet. `All`
matches everything.

### `PolicyCondition`

A requirement that must hold. The set is closed:

- `CallerIs(IdentityId)` — the caller is the given identity.
- `RequiresCaller` — the operation has an authenticated caller.
- `KeyStatusIn(Vec<KeyStatus>)` — the key's status is one of these.
- `NotBefore(Timestamp)` — the operation happens at or after this
  time.
- `NotAfter(Timestamp)` — the operation happens strictly before this
  time.
- `KeyNotIn(Vec<KeyId>)` — the key is not one of these.
- `RequiresAttestation` — hardware attestation is available.

A condition that needs data the context does not carry (for example,
`CallerIs` when there is no caller) is simply **not satisfied**. The
rule does not apply. It is not an error.

### `PolicyEffect`

- `Allow` — permit when the rule applies.
- `Deny { reason }` — refuse when the rule applies. The reason is
  surfaced in audit records and diagnostics.

### `Policy`

The rule itself:

- `label` — human-readable, never used for matching.
- `operations` — which operations the rule covers.
- `target` — what the rule applies to.
- `conditions` — extra requirements.
- `effect` — what to do when the rule applies.

Constructed with a small builder:

```rust
use nexusq_core::policy::{
    Policy, PolicyEffect, PolicyOperation, PolicyTarget, PolicyCondition,
};

let rule = Policy::new("allow-signing", PolicyEffect::Allow)
    .for_operations(vec![PolicyOperation::Sign, PolicyOperation::Verify])
    .on(PolicyTarget::AnyKey)
    .and_condition(PolicyCondition::RequiresCaller);
```

PolicySet

An ordered list of rules. PolicySet::new() is empty. add(rule)
appends. evaluate(&context) returns a PolicyDecision.

Context

The evaluator does not read any hidden state. It receives a
PolicyContext built by the caller (in practice, by the session):

· operation — the operation being attempted.
· caller — the caller's IdentityId, if authenticated.
· key_id, key_status — the key being used and its current status.
· identity_id — the identity being used.
· now — the current time.
· hardware_attested — whether attestation is available.

A context with no caller will not satisfy CallerIs or
RequiresCaller. A context with no key will not satisfy KeyStatusIn
or KeyNotIn; it also will not match a target of AnyKey or
Key(_).

Session integration

Session consults the engine before every auditable operation. The
list (from vault/container.rs) maps operations to their
PolicyOperation:

Session method PolicyOperation
generate_key KeyCreate
activate_key KeyActivate
rotate_key KeyRotate
revoke_key KeyRevoke
destroy_key KeyDestroy
create_identity IdentityCreate
identity_sign IdentitySign
rotate_identity_key IdentityRotateKey
revoke_identity IdentityRevoke
issue_credential CredentialIssue
encrypt, encrypt_file EnvelopeSeal
decrypt, decrypt_file EnvelopeOpen

verify_credential is not policy-checked: it only reads public
information.

A refused operation returns VaultError::PolicyDenied(decision). If
auditing is enabled, a KeyAccessDenied event with the Denied
outcome is recorded before the error returns. This is what makes
a policy violation visible.

A note on the context's optional fields

The current session does not fill caller or hardware_attested:
there is no notion of "who unlocked the vault" yet, and the software
backend reports no attestation.

This means:

· PolicyCondition::RequiresCaller never holds, so any rule that
  uses it will not apply. A set that only contains such rules will
  deny everything (default-deny).
· PolicyCondition::RequiresAttestation never holds either, for the
  same reason.

These limitations are documented behavior, not bugs. They will be
lifted when the session gains a caller identity (planned) and when a
hardware backend that can attest is available (Fase 9's traits are
already in place).

What the engine does not do

· Rate limiting. The engine is stateless: it looks at the current
  context, not at how often an operation has happened. Rate limits
  are a v1.x concern and need state the evaluator deliberately does
  not carry.
· Role-based access control. There are no roles, only identities
  and conditions. RBAC can be layered on top: each role becomes a set
  of identities, and rules reference them with CallerIs.
· Delegate authorization. An identity cannot grant its
  permissions to another identity. Delegation is a distributed
  problem the engine does not attempt.
· Enforce anything by itself. PolicySet::evaluate is a pure
  function: give it a context, get a decision. Enforcement — calling
  it and acting on the result — is the session's job.

Testing a policy

There are two ways to test a policy:

1. Unit-level: build a PolicySet, build a PolicyContext, call
   evaluate, assert on the PolicyDecision. This is what
   policy/set.rs tests do, and it is fast and deterministic.
2. Integration-level: create a vault, attach a set, run real
   operations, observe the outcome. This is what
   tests/policy_e2e.rs does.

Both are useful. Use unit tests for rule semantics and integration
tests for the wiring.

Reference

· docs/SECURITY_MODEL.md §5.2 — authorization design
· docs/THREAT_MODEL.md T-08 — key misuse
· docs/KEY_MANAGEMENT.md §6.2 — algorithm / purpose mapping
· docs/STORAGE.md §7 — audit log
  EOF
  wc -l docs/POLICY.md && head -10 docs/POLICY.md
