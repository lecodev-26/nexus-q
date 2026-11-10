# NEXUS-Q AI-assisted security audit

This directory contains the manually triggered OpenRouter free-model coordinator, profile budgets, and the vendored Cloudflare security-audit methodology.

Start with [the operator guide](../docs/security/AI_SECURITY_AUDIT.md). The workflow is `.github/workflows/ai-security-audit.yml`.

The first version is static-only: it reads tracked text files, performs bounded sequential model review, validates structured output with the vendored upstream validators, and writes reports to the Actions runner's temporary directory. It does not execute target code, install target dependencies, run tests, create commits, or change the repository.
