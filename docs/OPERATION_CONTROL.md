# Vault operation control

`nexusq_core::vault::OperationControl` is a cloneable cancellation handle backed by an atomic flag. The worker owns one clone and the UI-facing registry keeps another, allowing cancellation requests without taking the vault session lock.

Cancellation is cooperative. Core methods check the flag at safe boundaries; they do not interrupt Argon2, authenticated-encryption primitives, or another in-flight cryptographic operation. Callers must therefore keep the UI in a `cancelling` state until the worker reaches a checkpoint and returns.

`OperationProgress` reports a phase and optional measured completed/total units. A phase-only update is deliberately indeterminate. Current file-envelope operations process payloads in memory, so they report completed input/output I/O stages and an indeterminate cryptographic phase rather than inventing byte-level encryption progress. Folder workflows can report completed files out of the manifest's validated file count.

Controlled file and backup exporters publish with create-only semantics and clean up temporary or newly-published outputs if a later step fails. The Vault application's controlled folder workflows remove incomplete destination trees on cancellation/failure. Backup import accepts cancellation before destination-vault creation; once creation starts it completes or removes the newly-created vault on failure.
