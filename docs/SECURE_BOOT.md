# Secure boot and measured boot

This document describes how NEXUS-Q relates to secure boot, measured
boot, and attestation on platforms that provide them, and what it
does on platforms that do not. It is the reference for the traits
`SecureBoot`, `MeasuredBoot`, `AttestationProvider` and
`AttestationVerifier` in `crates/nexusq-core/src/hardware/`.

## The three concepts

**Secure boot** is an enforcement mechanism. Each stage of the boot
chain verifies the signature of the next stage before handing over
control. If a signature fails, the device refuses to continue. The
chain typically starts at an immutable Boot ROM and ends at the
application.

**Measured boot** is an observation mechanism. Each stage computes a
digest of the next stage and extends a register that cannot be
rewritten afterwards. The stage is *not* rejected if the digest is
unexpected: the point is to record what happened, not to prevent it.
On TPM 2.0 the registers are called PCRs.

**Attestation** is how a device proves to a remote verifier what it
ran. It reads the measured registers, signs them (plus a nonce from
the verifier) with a key that only that hardware holds, and sends the
signed report. The verifier checks the signature against a known
root, checks the nonce for freshness, and compares the measurements
against a known-good reference.

The three fit together: secure boot enforces, measured boot records,
attestation reports.

## How NEXUS-Q exposes them

The hardware module in `nexusq-core` defines four traits:

| Trait                  | Purpose                                           |
|------------------------|---------------------------------------------------|
| `SecureBoot`           | Report whether the boot chain verified.           |
| `MeasuredBoot`         | Read the measured registers.                      |
| `AttestationProvider`  | Produce a signed attestation report.              |
| `AttestationVerifier`  | Check a report against a policy.                  |

They live in `crates/nexusq-core/src/hardware/` and are re-exported
from the module root. Every backend groups one implementation of
each, alongside `RandomSource`, `SecureStorage`, `KeyProvider` and
`SecureMemory` behind the `Backend` trait.

## What each backend provides

### Software backend

The software backend runs anywhere. It implements every trait with
the most honest answer available:

- `SecureBoot::state()` returns `Unknown`. A general-purpose OS does
  not expose the boot chain to user space. Returning `Verified`
  without evidence would be a lie.
- `MeasuredBoot::registers()` returns `NotAvailable`. An empty list
  would be worse: a caller could mistake "no registers" for "boot
  verified with no measurements".
- `AttestationProvider::is_available()` returns `false`.
- `AttestationVerifier::verify()` returns `NotSupported`. With no
  root of trust, no signature can be checked.

This is deliberate. A deployment that requires secure boot on the
software backend must be configured to refuse to start. NEXUS-Q does
not pretend.

### Hardware backends (future)

Each future backend will implement the traits using the platform's
facilities:

- **TPM 2.0**: `SecureBoot` derives its state from the platform
  configuration registers and the boot chain, `MeasuredBoot` reads
  PCRs 0–23, `AttestationProvider` produces TPM quotes, and
  `AttestationVerifier` checks them against a stored EK/AIK.
- **Secure Element**: `SecureBoot` reports the SE's verified state,
  `MeasuredBoot` returns the SE's monotonic counters and
  measurements, attestation uses the SE's signing key.
- **RISC-V**: on a board with a secure boot ROM and a TPM or SE,
  the same three traits map to the board's boot ROM measurements,
  the TPM PCRs, and TPM quotes.
- **Enclave**: attestation is native; the enclave produces a signed
  report bound to the platform's root.

None of these are implemented in v1.0. The traits are in place so
that a backend can be added without changing any call site.

## Using the state

Two common patterns:

**Pattern A: require verified boot.**
A deployment that must not run on an unverified boot reads
`SecureBoot::state()` at startup. If the state is not
`SecureBootState::Verified { .. }`, it refuses to proceed. This is a
policy decision, not something the core library decides on its own.

**Pattern B: publish attestation.**
A device that wants to be trusted by a remote peer produces an
attestation report on request:

1. The peer sends a fresh nonce.
2. The device calls `AttestationProvider::attest(nonce)`.
3. The device sends the report back.
4. The peer constructs an `AttestationPolicy` with the nonce and the
   components it cares about, and calls
   `AttestationVerifier::verify(report, policy)`.
5. The verifier's backend checks the signature against its root of
   trust and runs the structural checks.

Step 5 is where the cryptography happens. NEXUS-Q provides the
structure (`verify_report_against_policy`) and leaves the root of
trust to the backend, because only the backend knows which keys to
believe.

## What NEXUS-Q does not do

- **It does not implement secure boot.** That belongs to the platform
  firmware. NEXUS-Q reads the result.
- **It does not manage PCRs.** The firmware extends them. NEXUS-Q
  reads them.
- **It does not store attestation roots.** A verifier must be
  configured with the keys it trusts. This is a deployment concern.
- **It does not enforce a policy by default.** `SecureBootState` is
  informational. A caller that cares must act on it.

## Threat model alignment

From `docs/THREAT_MODEL.md`:

- **O-01 (compromised OS)** is out of scope for the software
  backend. On a platform with a TPM or SE, an attestation report can
  detect that the OS has been modified.
- **O-03 (cold boot)** is out of scope. Secure boot does not protect
  against physical attacks after the device has booted.
- **A-root (privileged local attacker)** is mitigated, not defeated,
  when attestation is available: the attacker can still modify the
  runtime, but a remote verifier can detect the modification through
  the PCRs.

## Reference

- `docs/ARCHITECTURE.md` §2.3 — hardware-agnostic design
- `docs/THREAT_MODEL.md` — A-root, O-01, O-03
- `docs/CROSS_COMPILE.md` — building for RISC-V
- TCG TPM 2.0 specification (Platform Configuration Registers)
- NIST SP 800-155 — BIOS Integrity Measurement Guidelines
