//! Explicit cross-feature vault and public-key envelope interoperability harness.
//!
//! Security CI invokes this ignored test in separate RustCrypto, native, and
//! portable-backend builds. One configuration writes serialized artifacts;
//! another configuration opens the exact bytes and exercises the stored keys.

use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr as _;

use nexusq_core::crypto::kem::hybrid;
use nexusq_core::identity::IdentityId;
use nexusq_core::vault::container::Vault;
use nexusq_core::vault::envelope::{build_envelope_to_public_key, open_envelope_with_kem};

const PLAINTEXT: &[u8] = b"nexusq-cross-configuration-envelope-v1";
const KEY_SEED: [u8; hybrid::SECRET_KEY_LEN] = [0x42; hybrid::SECRET_KEY_LEN];
const VAULT_PASSWORD: &[u8] = b"nexusq-cross-configuration-vault-password";
const CREDENTIAL_CLAIMS: &[u8] = b"cross-configuration-vault-key-usable";

#[test]
#[ignore = "run explicitly across separate Cargo feature configurations in CI"]
fn cross_configuration_artifacts() {
    let pair = hybrid::from_secret_key_bytes(&KEY_SEED).expect("fixed hybrid seed is valid");
    let role = std::env::var("NQ_CROSS_CONFIG_ROLE").expect("CI must select write or read role");

    match role.as_str() {
        "write" => {
            let envelope_path = required_path("NQ_CROSS_CONFIG_ENVELOPE_PATH");
            let envelope = build_envelope_to_public_key(
                &pair.public_key_bytes(),
                PLAINTEXT,
                b"cross-config-test".to_vec(),
            )
            .expect("the configured provider must create the public-key envelope");
            fs::write(envelope_path, envelope)
                .expect("CI must be able to persist the serialized envelope");

            let vault_path = required_path("NQ_CROSS_CONFIG_VAULT_PATH");
            let vault = Vault::create(&vault_path, VAULT_PASSWORD, Some("cross-config".into()))
                .expect("the configured provider must create a vault");
            let mut session = vault.unlock(VAULT_PASSWORD).expect("new vault must unlock");
            let identity = session
                .create_identity(Some("cross-config-identity".into()))
                .expect("new vault must create an identity and its ML-DSA credential key");
            session
                .lock()
                .expect("writer must persist the populated vault");
            fs::write(identity_sidecar(&vault_path), identity.to_string())
                .expect("CI must be able to persist the test identity identifier");
        }
        "read" => {
            let envelope_paths = required_paths("NQ_CROSS_CONFIG_ENVELOPE_PATHS");
            assert!(
                !envelope_paths.is_empty(),
                "at least one cross-configuration envelope is required"
            );
            for path in envelope_paths {
                let bytes = fs::read(path)
                    .expect("the writer configuration must have created the envelope");
                let opened = open_envelope_with_kem(&pair, &bytes)
                    .expect("the reader configuration must open the writer's envelope");
                assert_eq!(
                    opened.as_slice(),
                    PLAINTEXT,
                    "cross-configuration plaintext mismatch"
                );
            }

            let vault_paths = required_paths("NQ_CROSS_CONFIG_VAULT_PATHS");
            assert!(
                !vault_paths.is_empty(),
                "at least one cross-configuration vault is required"
            );
            for path in vault_paths {
                let vault = Vault::open(&path).expect("reader must parse the writer's vault file");
                let session = vault
                    .unlock(VAULT_PASSWORD)
                    .expect("reader configuration must unlock the writer's vault");
                assert_eq!(session.identity_count(), 1);
                assert_eq!(session.key_count(), 2);

                let identity_text = fs::read_to_string(identity_sidecar(Path::new(&path)))
                    .expect("writer must have stored the test identity identifier");
                let identity = IdentityId::from_str(identity_text.trim())
                    .expect("stored identity identifier must remain parseable");
                let credential = session
                    .issue_credential(
                        &identity,
                        identity.clone(),
                        CREDENTIAL_CLAIMS.to_vec(),
                        None,
                    )
                    .expect("reader must use the persisted ML-DSA key to issue a credential");
                session
                    .verify_credential(&credential)
                    .expect("reader must verify the credential with the persisted public key");
            }
        }
        other => panic!("unsupported NQ_CROSS_CONFIG_ROLE {other:?}; expected write or read"),
    }
}

fn required_path(name: &str) -> PathBuf {
    PathBuf::from(std::env::var(name).unwrap_or_else(|_| panic!("CI must provide {name}")))
}

fn required_paths(name: &str) -> Vec<String> {
    let value = std::env::var(name).unwrap_or_else(|_| panic!("CI must provide {name}"));
    value
        .split(';')
        .filter(|path| !path.is_empty())
        .map(str::to_owned)
        .collect()
}

fn identity_sidecar(vault_path: &Path) -> String {
    format!("{}.identity", vault_path.display())
}
