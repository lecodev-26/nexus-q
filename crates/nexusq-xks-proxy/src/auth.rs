use std::time::{SystemTime, UNIX_EPOCH};

use axum::http::{HeaderMap, Method, Uri};
use hmac::KeyInit;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::protocol::{ErrorCode, XksError};

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
pub(crate) struct AuthCredential {
    pub access_key_id: String,
    pub secret_access_key: Zeroizing<String>,
}

#[derive(Clone)]
pub(crate) struct AuthConfig {
    pub credentials: Vec<AuthCredential>,
}

pub(crate) fn verify(
    config: &AuthConfig,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<(), XksError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| denied())?
        .as_secs();
    verify_at(config, method, uri, headers, body, now)
}

fn verify_at(
    config: &AuthConfig,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    body: &[u8],
    now: u64,
) -> Result<(), XksError> {
    let authorization = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(denied)?;
    let date = headers
        .get("x-amz-date")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(denied)?;
    let host = headers
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .or_else(|| uri.authority().map(|authority| authority.as_str()))
        .ok_or_else(denied)?;

    let timestamp = parse_timestamp(date).ok_or_else(denied)?;
    if now.abs_diff(timestamp) > 300 {
        return Err(denied());
    }

    let fields = authorization
        .strip_prefix("AWS4-HMAC-SHA256 ")
        .ok_or_else(denied)?;
    let credential_scope = field(fields, "Credential=").ok_or_else(denied)?;
    let supplied_signature = field(fields, "Signature=")
        .filter(|signature| {
            signature.len() == 64 && signature.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
        .ok_or_else(denied)?;
    let (credential, scope_parts) = config
        .credentials
        .iter()
        .find_map(|candidate| {
            credential_scope
                .strip_prefix(&format!("{}/", candidate.access_key_id))
                .map(|scope| (candidate, scope.split('/').collect::<Vec<_>>()))
        })
        .ok_or_else(denied)?;
    if scope_parts.len() != 4
        || scope_parts[1].is_empty()
        || scope_parts[2] != "kms-xks-proxy"
        || scope_parts[3] != "aws4_request"
        || scope_parts[0] != &date[..8]
    {
        return Err(denied());
    }
    let payload_hash = hex(&Sha256::digest(body));
    if uri.query().is_some() || host.len() + uri.path().len() + 8 > 256 {
        return Err(XksError::new(
            ErrorCode::InvalidUriPath,
            "XKS request URI is invalid or too long",
        ));
    }
    let canonical = format!(
        "{method}\n{path}\n\nhost:{host}\nx-amz-date:{date}\n\nhost;x-amz-date\n{payload_hash}",
        method = method.as_str(),
        path = uri.path(),
        host = host.trim(),
    );
    let canonical_hash = hex(&Sha256::digest(canonical.as_bytes()));
    let scope = format!(
        "{}/{}/kms-xks-proxy/aws4_request",
        scope_parts[0], scope_parts[1]
    );
    let string_to_sign = format!("AWS4-HMAC-SHA256\n{date}\n{scope}\n{canonical_hash}");

    let mut prefixed_secret =
        Zeroizing::new(Vec::with_capacity(4 + credential.secret_access_key.len()));
    prefixed_secret.extend_from_slice(b"AWS4");
    prefixed_secret.extend_from_slice(credential.secret_access_key.as_bytes());
    let k_date = Zeroizing::new(hmac(prefixed_secret.as_slice(), scope_parts[0].as_bytes())?);
    let k_region = Zeroizing::new(hmac(&k_date, scope_parts[1].as_bytes())?);
    let k_service = Zeroizing::new(hmac(&k_region, b"kms-xks-proxy")?);
    let k_signing = Zeroizing::new(hmac(&k_service, b"aws4_request")?);
    let expected = hex(&hmac(&k_signing, string_to_sign.as_bytes())?);
    if expected.len() != supplied_signature.len()
        || expected
            .as_bytes()
            .ct_eq(supplied_signature.to_ascii_lowercase().as_bytes())
            .unwrap_u8()
            != 1
    {
        return Err(denied());
    }
    Ok(())
}

fn field<'a>(header: &'a str, name: &str) -> Option<&'a str> {
    header
        .split(',')
        .map(str::trim)
        .find_map(|part| part.strip_prefix(name))
}
fn hmac(key: &[u8], data: &[u8]) -> Result<Vec<u8>, XksError> {
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| denied())?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}
fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0xf) as usize] as char);
    }
    out
}
fn parse_timestamp(value: &str) -> Option<u64> {
    if value.len() != 16 || value.as_bytes()[8] != b'T' || value.as_bytes()[15] != b'Z' {
        return None;
    }
    let b = value.as_bytes();
    if b.iter()
        .enumerate()
        .any(|(i, c)| i != 8 && i != 15 && !c.is_ascii_digit())
    {
        return None;
    }
    let number = |start: usize, end: usize| value.get(start..end)?.parse::<i64>().ok();
    let year = number(0, 4)?;
    let month = number(4, 6)?;
    let day = number(6, 8)?;
    let hour = number(9, 11)?;
    let minute = number(11, 13)?;
    let second = number(13, 15)?;
    if !(1..=12).contains(&month) || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let month_days = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if day < 1 || day > month_days[(month - 1) as usize] {
        return None;
    }
    let adjusted_year = year - if month <= 2 { 1 } else { 0 };
    let era = adjusted_year.div_euclid(400);
    let year_of_era = adjusted_year - era * 400;
    let adjusted_month = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * adjusted_month + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146097 + day_of_era - 719468;
    u64::try_from(days * 86400 + hour * 3600 + minute * 60 + second).ok()
}

fn denied() -> XksError {
    XksError::new(
        ErrorCode::AuthenticationFailed,
        "Request authentication failed",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderValue, header};

    const ACCESS: &str = "ABCDEFGHIJKLMNOPQRST";
    const SECRET: &str = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG";

    fn signed_headers(date: &str, body: &[u8], path: &str) -> HeaderMap {
        let region = "us-east-1";
        let host = "xks.example.test";
        let payload_hash = hex(&Sha256::digest(body));
        let canonical = format!(
            "POST\n{path}\n\nhost:{host}\nx-amz-date:{date}\n\nhost;x-amz-date\n{payload_hash}"
        );
        let canonical_hash = hex(&Sha256::digest(canonical.as_bytes()));
        let scope = format!("{}/{}/kms-xks-proxy/aws4_request", &date[..8], region);
        let string_to_sign = format!("AWS4-HMAC-SHA256\n{date}\n{scope}\n{canonical_hash}");
        let k_date = hmac(format!("AWS4{SECRET}").as_bytes(), date[..8].as_bytes()).unwrap();
        let k_region = hmac(&k_date, region.as_bytes()).unwrap();
        let k_service = hmac(&k_region, b"kms-xks-proxy").unwrap();
        let k_signing = hmac(&k_service, b"aws4_request").unwrap();
        let signature = hex(&hmac(&k_signing, string_to_sign.as_bytes()).unwrap());
        let authorization = format!(
            "AWS4-HMAC-SHA256 Credential={ACCESS}/{}/{region}/kms-xks-proxy/aws4_request, SignedHeaders=host;x-amz-date, Signature={signature}",
            &date[..8]
        );
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, HeaderValue::from_static(host));
        headers.insert("x-amz-date", HeaderValue::from_str(date).unwrap());
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&authorization).unwrap(),
        );
        headers
    }

    fn config() -> AuthConfig {
        AuthConfig {
            credentials: vec![AuthCredential {
                access_key_id: ACCESS.into(),
                secret_access_key: Zeroizing::new(SECRET.into()),
            }],
        }
    }

    #[test]
    fn parses_epoch_and_rejects_invalid_calendar_dates() {
        assert_eq!(parse_timestamp("19700101T000000Z"), Some(0));
        assert!(parse_timestamp("20260230T120000Z").is_none());
        assert!(parse_timestamp("20261116T246000Z").is_none());
    }

    #[test]
    fn accepts_valid_xks_sigv4_request() {
        let date = "20261116T100000Z";
        let body = br#"{"requestMetadata":{}}"#;
        let path = "/tenant/kms/xks/v1/health";
        let headers = signed_headers(date, body, path);
        assert!(
            verify_at(
                &config(),
                &Method::POST,
                &path.parse().unwrap(),
                &headers,
                body,
                parse_timestamp(date).unwrap()
            )
            .is_ok()
        );
    }

    #[test]
    fn rejects_modified_payload() {
        let date = "20261116T100000Z";
        let path = "/kms/xks/v1/health";
        let headers = signed_headers(date, b"original", path);
        assert!(
            verify_at(
                &config(),
                &Method::POST,
                &path.parse().unwrap(),
                &headers,
                b"modified",
                parse_timestamp(date).unwrap()
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_missing_headers_invalid_signature_scope_and_query() {
        let date = "20261116T100000Z";
        let path = "/kms/xks/v1/health";
        let body = b"body";
        let now = parse_timestamp(date).unwrap();
        let valid = signed_headers(date, body, path);

        let mut missing_auth = valid.clone();
        missing_auth.remove(header::AUTHORIZATION);
        assert!(
            verify_at(
                &config(),
                &Method::POST,
                &path.parse().unwrap(),
                &missing_auth,
                body,
                now
            )
            .is_err()
        );

        let mut bad_signature = valid.clone();
        bad_signature.insert(header::AUTHORIZATION, HeaderValue::from_static("AWS4-HMAC-SHA256 Credential=ABCDEFGHIJKLMNOPQRST/20261116/us-east-1/kms-xks-proxy/aws4_request, SignedHeaders=host;x-amz-date, Signature=xyz"));
        assert!(
            verify_at(
                &config(),
                &Method::POST,
                &path.parse().unwrap(),
                &bad_signature,
                body,
                now
            )
            .is_err()
        );

        let mut wrong_scope = valid.clone();
        wrong_scope.insert(header::AUTHORIZATION, HeaderValue::from_static("AWS4-HMAC-SHA256 Credential=ABCDEFGHIJKLMNOPQRST/20261116/us-east-1/other/aws4_request, SignedHeaders=host;x-amz-date, Signature=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
        assert!(
            verify_at(
                &config(),
                &Method::POST,
                &path.parse().unwrap(),
                &wrong_scope,
                body,
                now
            )
            .is_err()
        );

        let query_path = "/kms/xks/v1/health?unexpected=1";
        let query_headers = signed_headers(date, body, query_path);
        assert!(
            verify_at(
                &config(),
                &Method::POST,
                &query_path.parse().unwrap(),
                &query_headers,
                body,
                now
            )
            .is_err()
        );

        let mut missing_host = valid;
        missing_host.remove(header::HOST);
        let uri: Uri = "https://xks.example.test/kms/xks/v1/health"
            .parse()
            .unwrap();
        assert!(verify_at(&config(), &Method::POST, &uri, &missing_host, body, now).is_ok());
    }

    #[test]
    fn rejects_stale_timestamp() {
        let date = "20000101T000000Z";
        let path = "/kms/xks/v1/health";
        let headers = signed_headers(date, b"body", path);
        assert!(
            verify_at(
                &config(),
                &Method::POST,
                &path.parse().unwrap(),
                &headers,
                b"body",
                parse_timestamp(date).unwrap() + 301
            )
            .is_err()
        );
    }
}
