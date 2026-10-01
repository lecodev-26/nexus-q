//! Command-line interface definition.
//!
//! Every subcommand is declared here with `clap`'s derive macros. The
//! actual work lives in `crate::commands::*`; this module only
//! describes the shape of the command line.
//!
//! See `docs/API.md` §6 for the command list.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

/// `nexusq` — command-line interface for AXIOM NEXUS-Q.
#[derive(Debug, Parser)]
#[command(
    name = "nexusq",
    version,
    about = "Post-quantum cryptographic security engine",
    long_about = None,
)]
pub struct Cli {
    /// Output format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Human, global = true)]
    pub output: OutputFormat,

    /// Suppress non-error output.
    #[arg(long, global = true)]
    pub quiet: bool,

    /// The subcommand to run.
    #[command(subcommand)]
    pub command: Command,
}

/// Output format for command results.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    /// Human-readable tables and messages.
    Human,
    /// Machine-readable JSON.
    Json,
}

/// Top-level subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Manage vaults.
    #[command(subcommand)]
    Vault(VaultCommand),

    /// Manage keys.
    #[command(subcommand)]
    Key(KeyCommand),

    /// Encrypt and decrypt data.
    #[command(subcommand)]
    Data(DataCommand),

    /// Sign and verify messages.
    #[command(subcommand)]
    Sign(SignCommand),

    /// Manage identities.
    #[command(subcommand)]
    Identity(IdentityCommand),

    /// Issue and verify credentials.
    #[command(subcommand)]
    Credential(CredentialCommand),

    /// Inspect and verify the audit log.
    #[command(subcommand)]
    Audit(AuditCommand),
}

// =============================================================================
// Vault
// =============================================================================

/// Vault subcommands.
#[derive(Debug, Subcommand)]
pub enum VaultCommand {
    /// Create a new vault at the given path.
    Create(VaultCreateArgs),
    /// Show a vault's status without unlocking it.
    Status(VaultStatusArgs),
}

/// Arguments for `vault create`.
#[derive(Debug, Args)]
pub struct VaultCreateArgs {
    /// Path of the vault file to create.
    pub path: PathBuf,

    /// Optional human-readable label.
    #[arg(long)]
    pub label: Option<String>,

    /// Read the password from a file instead of prompting.
    ///
    /// The file's contents are used verbatim, with one trailing
    /// newline stripped. Intended for scripts and CI.
    #[arg(long, value_name = "PATH")]
    pub password_file: Option<PathBuf>,
}

/// Arguments for `vault status`.
#[derive(Debug, Args)]
pub struct VaultStatusArgs {
    /// Path of the vault file.
    pub path: PathBuf,
}

// =============================================================================
// Key
// =============================================================================

/// Key subcommands.
#[derive(Debug, Subcommand)]
pub enum KeyCommand {
    /// Generate a new key inside the vault.
    Generate(KeyGenerateArgs),
    /// List every key in the vault.
    List(KeyListArgs),
    /// Show a key's metadata.
    Info(KeyInfoArgs),
}

/// Arguments for `key generate`.
#[derive(Debug, Args)]
pub struct KeyGenerateArgs {
    /// Path of the vault file.
    pub vault: PathBuf,

    /// Algorithm for the new key.
    #[arg(long, value_enum)]
    pub algorithm: AlgorithmArg,

    /// Purpose of the new key.
    #[arg(long, value_enum)]
    pub purpose: PurposeArg,

    /// Activate the key immediately after creating it.
    #[arg(long)]
    pub activate: bool,

    /// Read the vault password from a file instead of prompting.
    #[arg(long, value_name = "PATH")]
    pub password_file: Option<PathBuf>,
}

/// Arguments for `key list`.
#[derive(Debug, Args)]
pub struct KeyListArgs {
    /// Path of the vault file.
    pub vault: PathBuf,

    /// Read the vault password from a file instead of prompting.
    #[arg(long, value_name = "PATH")]
    pub password_file: Option<PathBuf>,
}

/// Arguments for `key info`.
#[derive(Debug, Args)]
pub struct KeyInfoArgs {
    /// Path of the vault file.
    pub vault: PathBuf,

    /// Key identifier.
    pub key_id: String,

    /// Read the vault password from a file instead of prompting.
    #[arg(long, value_name = "PATH")]
    pub password_file: Option<PathBuf>,
}

/// Supported algorithms for the CLI.
///
/// The values match the canonical identifiers from
/// `nexusq_core::vault::Algorithm::as_str`, so the strings a user
/// types on the command line and the strings stored in the vault are
/// the same.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum AlgorithmArg {
    /// Ed25519 signing key.
    #[value(name = "ed25519")]
    Ed25519,
    /// ML-KEM-768 post-quantum KEM key.
    #[value(name = "mlkem768")]
    MlKem768,
    /// AES-256-GCM symmetric key.
    #[value(name = "aes256gcm")]
    Aes256Gcm,
    /// ChaCha20-Poly1305 symmetric key.
    #[value(name = "chacha20poly1305")]
    ChaCha20Poly1305,
}

/// Supported purposes for the CLI.
///
/// The values match the canonical identifiers from
/// `nexusq_core::vault::Purpose::as_str`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum PurposeArg {
    /// Signing.
    #[value(name = "sign")]
    Sign,
    /// Encryption.
    #[value(name = "encrypt")]
    Encrypt,
    /// Decryption.
    #[value(name = "decrypt")]
    Decrypt,
    /// Key agreement.
    #[value(name = "key_agreement")]
    KeyAgreement,
    /// Key wrapping.
    #[value(name = "wrap")]
    Wrap,
}

// =============================================================================
// Data
// =============================================================================

/// Data subcommands.
#[derive(Debug, Subcommand)]
pub enum DataCommand {
    /// Encrypt a file.
    Encrypt(DataEncryptArgs),
    /// Decrypt a file.
    Decrypt(DataDecryptArgs),
}

/// Arguments for `data encrypt`.
#[derive(Debug, Args)]
pub struct DataEncryptArgs {
    /// Path of the vault file.
    pub vault: PathBuf,

    /// Key to encrypt with.
    #[arg(long)]
    pub key_id: String,

    /// Optional metadata to embed in the envelope.
    #[arg(long)]
    pub metadata: Option<String>,

    /// Read the vault password from a file instead of prompting.
    #[arg(long, value_name = "PATH")]
    pub password_file: Option<PathBuf>,

    /// Input file to encrypt.
    pub input: PathBuf,
}

/// Arguments for `data decrypt`.
#[derive(Debug, Args)]
pub struct DataDecryptArgs {
    /// Path of the vault file.
    pub vault: PathBuf,

    /// Read the vault password from a file instead of prompting.
    #[arg(long, value_name = "PATH")]
    pub password_file: Option<PathBuf>,

    /// Input envelope file (`.nqx`).
    pub input: PathBuf,

    /// Output file to write plaintext to.
    #[arg(value_name = "OUTPUT")]
    pub output_path: PathBuf,
}

// =============================================================================
// Sign
// =============================================================================

/// Sign subcommands.
#[derive(Debug, Subcommand)]
pub enum SignCommand {
    /// Sign a file.
    Sign(SignSignArgs),
    /// Verify a signature.
    Verify(SignVerifyArgs),
}

/// Arguments for `sign sign`.
#[derive(Debug, Args)]
pub struct SignSignArgs {
    /// Path of the vault file.
    pub vault: PathBuf,

    /// Key to sign with.
    #[arg(long)]
    pub key_id: String,

    /// File to sign.
    pub input: PathBuf,
}

/// Arguments for `sign verify`.
#[derive(Debug, Args)]
pub struct SignVerifyArgs {
    /// Path of the vault file.
    pub vault: PathBuf,

    /// Key the signature was made with.
    #[arg(long)]
    pub key_id: String,

    /// File that was signed.
    pub input: PathBuf,

    /// Signature file.
    pub signature: PathBuf,
}

// =============================================================================
// Identity
// =============================================================================

/// Identity subcommands.
#[derive(Debug, Subcommand)]
pub enum IdentityCommand {
    /// Create a new identity.
    Create(IdentityCreateArgs),
    /// List identities in the vault.
    List(IdentityListArgs),
}

/// Arguments for `identity create`.
#[derive(Debug, Args)]
pub struct IdentityCreateArgs {
    /// Path of the vault file.
    pub vault: PathBuf,

    /// Optional label.
    #[arg(long)]
    pub label: Option<String>,

    /// Read the vault password from a file instead of prompting.
    #[arg(long, value_name = "PATH")]
    pub password_file: Option<PathBuf>,
}

/// Arguments for `identity list`.
#[derive(Debug, Args)]
pub struct IdentityListArgs {
    /// Path of the vault file.
    pub vault: PathBuf,

    /// Read the vault password from a file instead of prompting.
    #[arg(long, value_name = "PATH")]
    pub password_file: Option<PathBuf>,
}

// =============================================================================
// Credential
// =============================================================================

/// Credential subcommands.
#[derive(Debug, Subcommand)]
pub enum CredentialCommand {
    /// Issue a credential from an identity.
    Issue(CredentialIssueArgs),
    /// Verify a credential.
    Verify(CredentialVerifyArgs),
}

/// Arguments for `credential issue`.
#[derive(Debug, Args)]
pub struct CredentialIssueArgs {
    /// Path of the vault file.
    pub vault: PathBuf,

    /// Issuing identity.
    #[arg(long)]
    pub issuer: String,

    /// Subject identity.
    #[arg(long)]
    pub subject: String,

    /// Claims as a JSON string.
    #[arg(long)]
    pub claims: String,

    /// Output file for the credential.
    #[arg(value_name = "OUTPUT")]
    pub output_path: PathBuf,
}

/// Arguments for `credential verify`.
#[derive(Debug, Args)]
pub struct CredentialVerifyArgs {
    /// Path of the vault file.
    pub vault: PathBuf,

    /// Credential file.
    pub input: PathBuf,
}

// =============================================================================
// Audit
// =============================================================================

/// Audit subcommands.
#[derive(Debug, Subcommand)]
pub enum AuditCommand {
    /// Verify the audit chain.
    Verify(AuditVerifyArgs),
}

/// Arguments for `audit verify`.
#[derive(Debug, Args)]
pub struct AuditVerifyArgs {
    /// Directory containing audit segments.
    pub audit_dir: PathBuf,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory as _;

    #[test]
    fn cli_definition_is_valid() {
        // Will panic if two subcommands share a name or an argument
        // collides.
        Cli::command().debug_assert();
    }

    #[test]
    fn parses_vault_create() {
        let cli = Cli::try_parse_from(["nexusq", "vault", "create", "v.nqv"]).unwrap();
        match cli.command {
            Command::Vault(VaultCommand::Create(args)) => {
                assert_eq!(args.path, PathBuf::from("v.nqv"));
                assert!(args.label.is_none());
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parses_vault_create_with_label() {
        let cli =
            Cli::try_parse_from(["nexusq", "vault", "create", "v.nqv", "--label", "test"]).unwrap();
        match cli.command {
            Command::Vault(VaultCommand::Create(args)) => {
                assert_eq!(args.label.as_deref(), Some("test"));
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parses_key_generate() {
        let cli = Cli::try_parse_from([
            "nexusq",
            "key",
            "generate",
            "v.nqv",
            "--algorithm",
            "ed25519",
            "--purpose",
            "sign",
        ])
        .unwrap();
        match cli.command {
            Command::Key(KeyCommand::Generate(args)) => {
                assert_eq!(args.vault, PathBuf::from("v.nqv"));
                assert_eq!(args.algorithm, AlgorithmArg::Ed25519);
                assert_eq!(args.purpose, PurposeArg::Sign);
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn json_output_flag_is_global() {
        let cli = Cli::try_parse_from(["nexusq", "--output", "json", "vault", "status", "v.nqv"])
            .unwrap();
        assert_eq!(cli.output, OutputFormat::Json);
    }

    #[test]
    fn rejects_unknown_algorithm() {
        let result = Cli::try_parse_from([
            "nexusq",
            "key",
            "generate",
            "v.nqv",
            "--algorithm",
            "rsa",
            "--purpose",
            "sign",
        ]);
        assert!(result.is_err());
    }
}
