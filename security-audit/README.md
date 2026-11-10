# NEXUS-Q AI-assisted security audit

This directory contains the manually triggered OpenRouter free-model coordinator, profile budgets, and the vendored Cloudflare security-audit methodology.

Start with [the operator guide](../docs/security/AI_SECURITY_AUDIT.md). The workflow is `.github/workflows/ai-security-audit.yml`.

The first version is static-only: it reads tracked text files, performs bounded sequential model review, validates structured output with the vendored upstream validators, and writes reports to the Actions runner's temporary directory. It does not execute target code, install target dependencies, run tests, create commits, or change the repository.


Progress is checkpointed atomically after reconnaissance, every hunt batch, every validation batch, and every source-verification batch. `candidates.json` preserves raw candidates if a later request is interrupted; `run-metadata.json` records the last completed phase and request count. The coverage ledger distinguishes fully reviewed, candidate, partially reviewed/blocked, and deferred surfaces. A separate lightweight workflow tests the coordinator and vendored validators without an OpenRouter key or Rust build.
