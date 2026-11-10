# Archived GitHub Actions workflows

These YAML files are historical references and are deliberately stored outside `.github/workflows/`, so GitHub Actions will not register or run them. The former sequential pipeline was retired when the repository moved to a deliberately small automatic CI entry point plus independently dispatched engineering, security, benchmark, SDK, native-backend, publication, and release workflows.

Do not restore an archived workflow without reviewing its branch/version assumptions, runner availability, permissions, secrets, and publication side effects. Current entry points are documented in [`docs/ci-pipeline.md`](../../docs/ci-pipeline.md).
