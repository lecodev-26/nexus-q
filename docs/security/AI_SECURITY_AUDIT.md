# AI-assisted Security Audit

NEXUS-Q provides a separate, manually triggered static security review using OpenRouter. It does not replace Fast CI, `cargo audit`, `cargo deny`, Gitleaks, fuzzing, code review, or an independent security assessment.

## Running it

1. Open **Actions → NEXUS-Q AI-assisted Security Audit**.
2. Select **Run workflow** on `main`.
3. Choose `quick`, `standard`, or `deep`.
4. Download the `nexusq-ai-security-audit-...` artifact when the run finishes.

The workflow is manual-only and is gated to `main`. It does not run for pushes or pull requests, does not comment on PRs, and does not modify repository files.

## Free-only model policy

The coordinator discovers models through OpenRouter's public model catalogue and selects only model IDs ending in `:free` whose prompt and completion prices are both zero. It does not use `openrouter/free`, paid model IDs, paid fallbacks, credit top-ups, or automatic retries. If no eligible model is available, the run stops before sending source code. HTTP 429/quota exhaustion stops further requests and preserves partial reports.

The single required credential is the GitHub Actions **repository secret** `OPENROUTER_API_KEY`. Do not store it as a repository variable. The key is passed only to the coordinator process; it is never written to reports or included in model prompts.

Free model availability and provider limits are controlled by OpenRouter and can change. The coordinator uses bounded request budgets: Quick 8, Standard 18, Deep 35 inference requests per run. OpenRouter's published free-variant limits may also apply (currently 20 requests/minute and 50/day for `:free` variants); failed requests can count against the daily quota. No paid fallback is attempted.

## What this version does

- Reads tracked source and selected security/architecture documentation as text.
- Excludes binary files, lockfiles, vendored dependencies, build output, obvious secret/key paths, and symlinks; redacts common private-key and token patterns.
- Runs sequential logical phases: reconnaissance, coverage-led static hunting, adversarial candidate review, structured findings, and a separate source-claim verification pass.
- Produces `REPORT.md`, `FINDINGS-DETAIL.md`, `NEEDS-VALIDATION.md`, `findings.json`, `candidates.json`, `coverage-ledger.json`, `run-metadata.json`, and `architecture.md`.
- Atomically checkpoints candidates, request counts, the last completed phase, and coverage after each completed model batch. If a later request fails, the artifact retains earlier candidates and marks incomplete coverage as blocked or deferred rather than claiming it was reviewed.
- Preserves complete source input when batching: exceptionally long lines are split into individually tracked sub-line fragments, and a file is covered only after every planned fragment completes. Coverage records all selected paths (without a 30-path truncation); kernel and Python binding crates are included in their corresponding surfaces.
- Keeps findings at `needs_validation` unless independently demonstrated evidence exists. This static-only implementation does not mark a vulnerability confirmed and does not assign severity to unverified candidates.
- A separate **AI Security Audit — lightweight validation** workflow runs Python helper tests and the vendored Node.js validator suites on relevant PRs/pushes. It requires no API key and performs no Rust build.

## Explicit limitations

This is an API-assisted static triage coordinator, not a multi-agent runtime. Its logical roles are sequential prompts to a model; they are not isolated subagents, and a second model call is not equivalent to an independent human or agent review. Model output is untrusted and must be reviewed.

No target-controlled code, build scripts, tests, binaries, package installation, fuzzers, browsers, or networked target processes are executed. No dynamic reproduction is performed. Candidates requiring runtime, deployment, provider, HSM, hardware, or operational evidence remain `needs_validation` with a proposed safe validation plan.

The vendored Cloudflare security-audit skill is included under `security-audit/cloudflare-skill/` under its MIT license and pinned upstream commit. Its full six-phase workflow requires a coding agent with delegation and an OS-enforced sandbox; this workflow deliberately does not claim to implement those capabilities.

## Safety boundaries

- Workflow is manually dispatched from `main` only.
- Workflow permissions are read-only (`contents: read`); checkout credentials are not persisted.
- No GitHub token is passed to the coordinator.
- No source writes, commits, PRs, comments, deployments, or paid API requests are performed.
- Source snippets are sent to the selected third-party model provider. Do not run this workflow on repositories containing material that must not leave your approved environment.
- The audit artifact is retained by GitHub Actions for 30 days.
