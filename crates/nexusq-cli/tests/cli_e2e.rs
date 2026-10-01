//! End-to-end tests for the `nexusq` binary.
//!
//! Each test spawns the compiled binary with real arguments, sets up
//! temporary vaults and audit directories, and checks both the exit
//! code and the printed output. They see the same surface a user of
//! the CLI sees.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use tempfile::TempDir;

/// Path to the compiled `nexusq` binary.
fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_nexusq")
}

/// Runs `nexusq` with the given arguments from a working directory.
fn run_in(dir: &Path, args: &[&str]) -> Output {
    Command::new(binary())
        .current_dir(dir)
        .args(args)
        .output()
        .expect("failed to spawn nexusq")
}

/// Runs `nexusq` with the given arguments from the test's directory.
fn run(args: &[&str]) -> Output {
    Command::new(binary())
        .args(args)
        .output()
        .expect("failed to spawn nexusq")
}

/// Returns the stdout of a successful run as a string.
fn stdout_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// Returns the exit code of a run.
fn code_of(output: &Output) -> i32 {
    output.status.code().unwrap_or(-1)
}

/// Writes a password file next to the test's temporary directory.
fn write_password(dir: &Path, name: &str, password: &str) -> PathBuf {
    let path = dir.join(name);
    fs::write(&path, password).unwrap();
    path
}

// =============================================================================
// Global commands
// =============================================================================

#[test]
fn version_exits_zero_and_prints_name() {
    let out = run(&["--version"]);
    assert_eq!(code_of(&out), 0);
    assert!(stdout_of(&out).contains("nexusq"));
}

#[test]
fn help_lists_every_subcommand() {
    let out = run(&["--help"]);
    assert_eq!(code_of(&out), 0);
    let text = stdout_of(&out);
    for cmd in [
        "vault",
        "key",
        "data",
        "sign",
        "identity",
        "credential",
        "audit",
    ] {
        assert!(text.contains(cmd), "help does not mention {cmd}");
    }
}

#[test]
fn unknown_subcommand_exits_with_usage_error() {
    let out = run(&["nonsense"]);
    assert_ne!(code_of(&out), 0);
}

// =============================================================================
// Vault lifecycle
// =============================================================================

#[test]
fn vault_create_and_status_roundtrip() {
    let dir = TempDir::new().unwrap();
    let pw = write_password(dir.path(), "pw.txt", "test-pass");

    let create = run_in(
        dir.path(),
        &[
            "vault",
            "create",
            "test.nqv",
            "--label",
            "demo",
            "--password-file",
            pw.to_str().unwrap(),
        ],
    );
    assert_eq!(code_of(&create), 0);
    assert!(dir.path().join("test.nqv").exists());

    let status = run_in(dir.path(), &["vault", "status", "test.nqv"]);
    assert_eq!(code_of(&status), 0);
    let text = stdout_of(&status);
    assert!(text.contains("argon2id"));
    assert!(text.contains("locked"));
}

#[test]
fn vault_status_missing_file_exits_io() {
    let dir = TempDir::new().unwrap();
    let out = run_in(dir.path(), &["vault", "status", "missing.nqv"]);
    assert_eq!(code_of(&out), 7);
}

#[test]
fn wrong_password_exits_authentication() {
    let dir = TempDir::new().unwrap();
    let good = write_password(dir.path(), "good.txt", "right");
    let bad = write_password(dir.path(), "bad.txt", "wrong");

    let create = run_in(
        dir.path(),
        &[
            "vault",
            "create",
            "test.nqv",
            "--password-file",
            good.to_str().unwrap(),
        ],
    );
    assert_eq!(code_of(&create), 0);

    let out = run_in(
        dir.path(),
        &[
            "key",
            "list",
            "test.nqv",
            "--password-file",
            bad.to_str().unwrap(),
        ],
    );
    assert_eq!(code_of(&out), 3);
}

// =============================================================================
// Key, data, identity, sign, credential, audit
// =============================================================================

/// Creates a vault at `dir/test.nqv` with `dir/pw.txt` as the
/// password and returns the password path.
fn setup_vault(dir: &TempDir) -> PathBuf {
    let pw = write_password(dir.path(), "pw.txt", "test-pass");
    let create = run_in(
        dir.path(),
        &[
            "vault",
            "create",
            "test.nqv",
            "--password-file",
            pw.to_str().unwrap(),
        ],
    );
    assert_eq!(code_of(&create), 0, "vault create failed");
    pw
}

#[test]
fn key_generate_list_and_info() {
    let dir = TempDir::new().unwrap();
    let pw = setup_vault(&dir);

    let gen_out = run_in(
        dir.path(),
        &[
            "key",
            "generate",
            "test.nqv",
            "--algorithm",
            "ed25519",
            "--purpose",
            "sign",
            "--activate",
            "--password-file",
            pw.to_str().unwrap(),
        ],
    );
    assert_eq!(code_of(&gen_out), 0);
    let gen_text = stdout_of(&gen_out);
    assert!(gen_text.contains("nqk_ed25519_"));

    let list = run_in(
        dir.path(),
        &[
            "key",
            "list",
            "test.nqv",
            "--password-file",
            pw.to_str().unwrap(),
        ],
    );
    assert_eq!(code_of(&list), 0);
    assert!(stdout_of(&list).contains("ed25519"));
}

#[test]
fn data_encrypt_decrypt_roundtrip() {
    let dir = TempDir::new().unwrap();
    let pw = setup_vault(&dir);

    // Generate an AES key for encrypt.
    let gen_out = run_in(
        dir.path(),
        &[
            "key",
            "generate",
            "test.nqv",
            "--algorithm",
            "aes256gcm",
            "--purpose",
            "encrypt",
            "--activate",
            "--password-file",
            pw.to_str().unwrap(),
        ],
    );
    assert_eq!(code_of(&gen_out), 0);

    // Extract the key id from the JSON list output.
    let list = run_in(
        dir.path(),
        &[
            "--output",
            "json",
            "key",
            "list",
            "test.nqv",
            "--password-file",
            pw.to_str().unwrap(),
        ],
    );
    assert_eq!(code_of(&list), 0);
    let list_text = stdout_of(&list);
    let key_id = extract_first_json_string(&list_text, "key_id").expect("no key_id in list output");

    // Encrypt a file.
    fs::write(dir.path().join("plain.txt"), b"hello, world").unwrap();
    let enc = run_in(
        dir.path(),
        &[
            "data",
            "encrypt",
            "test.nqv",
            "plain.txt",
            "--key-id",
            &key_id,
            "--password-file",
            pw.to_str().unwrap(),
        ],
    );
    assert_eq!(code_of(&enc), 0, "encrypt failed: {}", stdout_of(&enc));
    assert!(dir.path().join("plain.txt.nqx").exists());

    // Decrypt it back.
    let dec = run_in(
        dir.path(),
        &[
            "data",
            "decrypt",
            "test.nqv",
            "plain.txt.nqx",
            "plain.out",
            "--password-file",
            pw.to_str().unwrap(),
        ],
    );
    assert_eq!(code_of(&dec), 0);
    assert_eq!(
        fs::read(dir.path().join("plain.out")).unwrap(),
        b"hello, world"
    );
}

#[test]
fn identity_create_and_list() {
    let dir = TempDir::new().unwrap();
    let pw = setup_vault(&dir);

    let create = run_in(
        dir.path(),
        &[
            "identity",
            "create",
            "test.nqv",
            "--label",
            "alice",
            "--password-file",
            pw.to_str().unwrap(),
        ],
    );
    assert_eq!(code_of(&create), 0);
    assert!(stdout_of(&create).contains("nqi_"));

    let list = run_in(
        dir.path(),
        &[
            "identity",
            "list",
            "test.nqv",
            "--password-file",
            pw.to_str().unwrap(),
        ],
    );
    assert_eq!(code_of(&list), 0);
    assert!(stdout_of(&list).contains("alice"));
}

#[test]
fn sign_and_verify_roundtrip() {
    let dir = TempDir::new().unwrap();
    let pw = setup_vault(&dir);

    // Create an identity and capture its id from JSON output.
    let create = run_in(
        dir.path(),
        &[
            "--output",
            "json",
            "identity",
            "create",
            "test.nqv",
            "--label",
            "signer",
            "--password-file",
            pw.to_str().unwrap(),
        ],
    );
    assert_eq!(code_of(&create), 0);
    let identity = extract_first_json_string(&stdout_of(&create), "identity_id")
        .expect("no identity_id in output");

    // Write and sign a document.
    fs::write(dir.path().join("doc.txt"), b"signed content").unwrap();
    let sign = run_in(
        dir.path(),
        &[
            "sign",
            "sign",
            "test.nqv",
            "doc.txt",
            "--identity",
            &identity,
            "--password-file",
            pw.to_str().unwrap(),
        ],
    );
    assert_eq!(code_of(&sign), 0);
    assert!(dir.path().join("doc.txt.sig").exists());

    // Verify.
    let verify = run_in(
        dir.path(),
        &[
            "sign",
            "verify",
            "test.nqv",
            "doc.txt",
            "doc.txt.sig",
            "--identity",
            &identity,
            "--password-file",
            pw.to_str().unwrap(),
        ],
    );
    assert_eq!(code_of(&verify), 0);

    // Tamper and verify again: exit code 5.
    fs::write(dir.path().join("doc.txt"), b"tampered content").unwrap();
    let verify_bad = run_in(
        dir.path(),
        &[
            "sign",
            "verify",
            "test.nqv",
            "doc.txt",
            "doc.txt.sig",
            "--identity",
            &identity,
            "--password-file",
            pw.to_str().unwrap(),
        ],
    );
    assert_eq!(code_of(&verify_bad), 5);
}

#[test]
fn credential_issue_and_verify() {
    let dir = TempDir::new().unwrap();
    let pw = setup_vault(&dir);

    let alice = create_identity(&dir, &pw, "alice");
    let bob = create_identity(&dir, &pw, "bob");

    let issue = run_in(
        dir.path(),
        &[
            "credential",
            "issue",
            "test.nqv",
            "--issuer",
            &alice,
            "--subject",
            &bob,
            "--claims",
            "{\"role\":\"admin\"}",
            "--password-file",
            pw.to_str().unwrap(),
            "bob.nqc",
        ],
    );
    assert_eq!(code_of(&issue), 0);
    assert!(dir.path().join("bob.nqc").exists());

    let verify = run_in(
        dir.path(),
        &[
            "credential",
            "verify",
            "test.nqv",
            "bob.nqc",
            "--password-file",
            pw.to_str().unwrap(),
        ],
    );
    assert_eq!(code_of(&verify), 0);
    assert!(stdout_of(&verify).contains("admin"));
}

#[test]
fn audit_verify_on_fresh_dir_succeeds() {
    let dir = TempDir::new().unwrap();
    fs::create_dir(dir.path().join("audit")).unwrap();

    let out = run_in(dir.path(), &["audit", "verify", "audit"]);
    assert_eq!(code_of(&out), 0);
    assert!(stdout_of(&out).contains("valid"));
}

#[test]
fn attach_audit_and_show_records_operations() {
    let dir = TempDir::new().unwrap();
    let pw = setup_vault(&dir);
    fs::create_dir(dir.path().join("audit")).unwrap();

    // Attach audit.
    let attach = run_in(
        dir.path(),
        &[
            "vault",
            "attach-audit",
            "test.nqv",
            "audit",
            "--password-file",
            pw.to_str().unwrap(),
        ],
    );
    assert_eq!(code_of(&attach), 0);

    // Generate a key; the audit log should record it.
    let gen_out = run_in(
        dir.path(),
        &[
            "key",
            "generate",
            "test.nqv",
            "--algorithm",
            "ed25519",
            "--purpose",
            "sign",
            "--activate",
            "--password-file",
            pw.to_str().unwrap(),
        ],
    );
    assert_eq!(code_of(&gen_out), 0);

    let show = run_in(dir.path(), &["audit", "show", "audit"]);
    assert_eq!(code_of(&show), 0);
    let text = stdout_of(&show);
    assert!(text.contains("audit_configured"));
    assert!(text.contains("key_created"));
    assert!(text.contains("key_activated"));
}

// =============================================================================
// Helpers
// =============================================================================

/// Creates an identity with the given label and returns its id.
fn create_identity(dir: &TempDir, pw: &Path, label: &str) -> String {
    let out = run_in(
        dir.path(),
        &[
            "--output",
            "json",
            "identity",
            "create",
            "test.nqv",
            "--label",
            label,
            "--password-file",
            pw.to_str().unwrap(),
        ],
    );
    assert_eq!(
        code_of(&out),
        0,
        "identity create failed: {}",
        stdout_of(&out)
    );
    extract_first_json_string(&stdout_of(&out), "identity_id").expect("no identity_id in output")
}

/// Extracts the first occurrence of `"<field>": "<value>"` in a JSON
/// blob. The CLI's output is small and well-formed, so a regex-free
/// scan is fine.
fn extract_first_json_string(text: &str, field: &str) -> Option<String> {
    let needle = format!("\"{field}\"");
    let start = text.find(&needle)? + needle.len();
    let rest = &text[start..];
    let colon = rest.find(':')? + 1;
    let rest = &rest[colon..];
    let open = rest.find('"')? + 1;
    let rest = &rest[open..];
    let close = rest.find('"')?;
    Some(rest[..close].to_string())
}
