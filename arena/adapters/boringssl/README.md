# BoringSSL Arena adapter status

BoringSSL currently exposes ML-KEM and ML-DSA implementations inside its FIPS BCM layer. The inspected source exports functions such as `BCM_mlkem768_generate_key`, `BCM_mlkem768_encap`, `BCM_mlkem768_decap`, and `BCM_mldsa65_generate_key`/`sign`/`verify`.

Those declarations live in `crypto/fipsmodule/bcm_interface.h`, which BoringSSL explicitly describes as the interface between BCM and the rest of libcrypto and says the separation is still a work in progress. It is not a stable public consumer API.

Therefore this Arena target remains `PLANNED`: no adapter is claimed until BoringSSL provides a supported public API suitable for an external benchmark harness, or a dedicated upstream-supported benchmark interface is identified. Linking an Arena runner directly against internal BCM symbols would make the comparison implementation-internal and version-fragile.

Pinned inspection reference: `dd73e69a4e86fa178a4d19033c691e9b42cc1088`.
