//! Standalone AWS KMS External Key Store (XKS) v1 proxy.
//!
//! The proxy deliberately depends on a provider interface rather than the vault
//! envelope API. Implementations must keep key material inside the external key
//! manager and perform AES-GCM operations there.

mod auth;
mod pkcs11;
mod protocol;
mod service;

pub use pkcs11::Pkcs11XksProvider;
pub use protocol::{
    DecryptRequest, DecryptResponse, EncryptRequest, EncryptResponse, ErrorCode,
    GetHealthStatusRequest, GetHealthStatusResponse, GetKeyMetadataRequest, GetKeyMetadataResponse,
    KeyStatus, RequestMetadata, XksError, encode_xks_aad,
};
pub use service::{ProviderCiphertext, SigV4Credential, XksKeyProvider, XksProxyConfig, router};
