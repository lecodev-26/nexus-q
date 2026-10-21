# Issue #68 — RFC 3161 timestamp authority

- Added `nexusq-tsa` for DER `TimeStampReq` parsing and CMS `TimeStampToken` creation with ML-DSA-65 signatures.
- SHA-256 is currently the only accepted message-imprint algorithm; parameters must be absent and the digest must be exactly 32 bytes. Unsupported policy OIDs and unknown critical request extensions are rejected. Nonces are echoed unchanged.
- The token contains `TSTInfo`, the TSA certificate, `SigningCertificateV2` (SHA-256 certificate hash), CMS content-type/message-digest attributes and an ML-DSA-65 signature. Tests verify the signed-attributes signature using the certificate public key.
- A TSA certificate must be v3, currently valid at issuance, match the configured signing key, have critical EKU containing only `id-kp-timeStamping`, `keyUsage` permitting `digitalSignature`, and `basicConstraints CA=FALSE`.
- Time is injectable. The default OS clock is for development; production should supply an audited synchronized source. Backwards time is rejected. Serial allocation and last-seen time are currently process-local and must become durable/transactional before HA use.
- The library returns the `TimeStampToken` CMS object. An HTTP endpoint must wrap it in RFC 3161 `TimeStampResp`; certificate path validation remains the caller's responsibility.
