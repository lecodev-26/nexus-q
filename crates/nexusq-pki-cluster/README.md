
## Replica transport

`HttpReplicaPeer` implements `ReplicaPeer` over HTTPS using a pinned/private root CA, a client TLS identity, a short request timeout, and a per-peer bearer token. `ReplicaNode` exposes prepare/commit/abort receiver routes and checks both the token hash and an explicit allowlist of leader IDs before touching its tenant journal. Mount each `ReplicaNode` under that tenant's internal URL prefix (for example `/tenants/alpha/`) and keep it behind a private reverse proxy that verifies client certificates; never expose `/internal/replica/*` on the public listener. The sender uses a synchronous HTTP client, so invoke HA writes from a blocking worker when called by an async runtime.

A consensus-backed lease provider must still grant/renew leases and fencing epochs; this crate does not pretend that an HTTP bearer token is consensus. A peer deployment should use a stable odd-sized node set, one journal per tenant per node, and failure-injection tests for loss of leader, loss of quorum, delayed commits and restore.
