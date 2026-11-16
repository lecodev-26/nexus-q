use std::{env, error::Error, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use nexusq_hsm::{Pkcs11AesKeyRef, Pkcs11Provider};
use nexusq_xks_proxy::{Pkcs11XksProvider, SigV4Credential, XksProxyConfig, router};
use serde::Deserialize;
use zeroize::Zeroizing;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FileConfig {
    uri_path: String,
    access_key_id: String,
    secret_access_key: Zeroizing<String>,
    #[serde(default)]
    additional_credentials: Vec<FileCredential>,
    pkcs11_module: String,
    pkcs11_slot_index: usize,
    pkcs11_pin: Zeroizing<String>,
    ekm_vendor: String,
    ekm_model: String,
    keys: Vec<KeyMapping>,
    health_check_key_ref: Pkcs11AesKeyRef,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FileCredential {
    access_key_id: String,
    secret_access_key: Zeroizing<String>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeyMapping {
    external_key_id: String,
    key_ref: Pkcs11AesKeyRef,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(env::var("RUST_LOG").unwrap_or_else(|_| "info".into()))
        .init();
    let config_path = env::var_os("NEXUSQ_XKS_CONFIG")
        .map(PathBuf::from)
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "NEXUSQ_XKS_CONFIG must point to a protected JSON configuration file",
            )
        })?;
    let raw = Zeroizing::new(std::fs::read_to_string(config_path)?);
    let mut file: FileConfig = serde_json::from_str(&raw)?;

    let addr = bind_address(
        env::var("NEXUSQ_XKS_BIND").ok(),
        env::var("NEXUSQ_XKS_TRUSTED_TLS_TERMINATION")
            .ok()
            .as_deref()
            == Some("1"),
    )?;

    let pin = std::mem::take(&mut *file.pkcs11_pin);
    let provider = Pkcs11Provider::connect(&file.pkcs11_module, file.pkcs11_slot_index, pin)?;
    let mappings = file
        .keys
        .into_iter()
        .map(|entry| (entry.external_key_id, entry.key_ref));
    let xks_provider = Arc::new(Pkcs11XksProvider::new(
        provider,
        mappings,
        file.health_check_key_ref,
        file.ekm_vendor,
        file.ekm_model,
    )?);
    let app = router(
        XksProxyConfig {
            uri_path: file.uri_path,
            access_key_id: file.access_key_id,
            secret_access_key: file.secret_access_key,
            additional_credentials: file
                .additional_credentials
                .into_iter()
                .map(|credential| SigV4Credential {
                    access_key_id: credential.access_key_id,
                    secret_access_key: credential.secret_access_key,
                })
                .collect(),
        },
        xks_provider.clone(),
    )?;

    let health_provider = xks_provider.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        interval.tick().await;
        loop {
            interval.tick().await;
            let provider = health_provider.clone();
            match tokio::task::spawn_blocking(move || provider.refresh_health()).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => tracing::warn!(%error, "XKS background health refresh failed"),
                Err(_) => tracing::warn!("XKS background health refresh task failed"),
            }
        }
    });

    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "NEXUS-Q XKS proxy listening behind the configured TLS boundary");
    axum::serve(listener, app).await?;
    Ok(())
}

fn bind_address(
    value: Option<String>,
    trusted_tls_termination: bool,
) -> Result<SocketAddr, Box<dyn Error>> {
    let addr: SocketAddr = value.unwrap_or_else(|| "127.0.0.1:9443".into()).parse()?;
    if !addr.ip().is_loopback() && !trusted_tls_termination {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "non-loopback bind requires a trusted TLS terminator and NEXUSQ_XKS_TRUSTED_TLS_TERMINATION=1",
        ).into());
    }
    Ok(addr)
}

#[cfg(test)]
mod tests {
    use super::{FileConfig, bind_address};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    #[test]
    fn defaults_to_loopback_and_requires_trusted_tls_for_public_bind() {
        assert_eq!(
            bind_address(None, false).unwrap(),
            "127.0.0.1:9443".parse::<SocketAddr>().unwrap()
        );
        assert!(bind_address(Some("0.0.0.0:9443".into()), false).is_err());
        assert_eq!(
            bind_address(Some("0.0.0.0:9443".into()), true).unwrap(),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 9443)
        );
        assert!(bind_address(Some("not-an-address".into()), true).is_err());
    }

    #[test]
    fn parses_proxy_config_and_defaults_additional_credentials() {
        let json = r#"{
            "uriPath":"/kms/xks/v1",
            "accessKeyId":"ABCDEFGHIJKLMNOPQRST",
            "secretAccessKey":"abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG",
            "pkcs11Module":"/usr/lib/softhsm/libsofthsm2.so",
            "pkcs11SlotIndex":0,
            "pkcs11Pin":"test-pin",
            "ekmVendor":"SoftHSM",
            "ekmModel":"SoftHSM2",
            "keys":[],
            "healthCheckKeyRef":{"id":[1,2,3],"label":"health","token_label":"token","token_serial":"serial"}
        }"#;
        let config: FileConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.uri_path, "/kms/xks/v1");
        assert!(config.additional_credentials.is_empty());
        assert_eq!(config.keys.len(), 0);
        assert_eq!(config.health_check_key_ref.token_serial(), "serial");
    }
}
