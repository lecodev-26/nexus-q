# Security Guide

NEXUS-Q is security infrastructure, not a guarantee that every deployment is secure.

## Threat model

Read [Threat Model](../THREAT_MODEL.md) before deciding whether NEXUS-Q fits a deployment.

The design assumes that cryptographic correctness, key lifecycle, storage integrity, authorization, and operational boundaries must fail closed.

## Important limits

NEXUS-Q does not by itself defeat:

- a fully compromised operating system or privileged local attacker;
- physical extraction or cold-boot attacks;
- insecure deployment of the server without a TLS boundary;
- compromised application code that legitimately asks NEXUS-Q to perform an allowed operation.

Hardware-backed security and attestation require actual platform support.

## Secret handling

Never log or commit:

- vault passwords;
- bearer tokens;
- private keys;
- vault files;
- generated audit/log files containing sensitive operational context.

Use file permissions and an external secret mechanism for production credentials.

## Server authentication

The current server uses one configured bearer token for protected endpoints. It is compared in constant time and must be at least 32 bytes.

This is not equivalent to a complete identity-management system. mTLS and signed-challenge authentication are architectural extensions, not current server transports.

## Policy

The policy engine is fail-closed once a policy set is attached. The current session does not populate caller identity or hardware-attestation context, so policies requiring those conditions will not apply successfully.

See [Policy](../POLICY.md) for exact semantics.
