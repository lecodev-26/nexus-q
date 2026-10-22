# X.509 interoperability checks

These checks operate on self-signed test certificates only. The examples generate private keys in memory and write certificates, not private keys.

```bash
cd /path/to/nexus-q
cargo run -p nexusq-x509 --example issue_root -- /tmp/nexusq-ml-dsa65.pem
cargo run -p nexusq-x509 --example issue_slh_root -- /tmp/nexusq-slh-dsa.pem
cargo run -p nexusq-x509 --features experimental-composite --example issue_composite_root -- /tmp/nexusq-composite.pem

# OpenSSL 3.5.9 verified ML-DSA-65 and SLH-DSA roots:
/tmp/nexusq-openssl-3.5.9/bin/openssl verify -CAfile /tmp/nexusq-ml-dsa65.pem /tmp/nexusq-ml-dsa65.pem
/tmp/nexusq-openssl-3.5.9/bin/openssl verify -CAfile /tmp/nexusq-slh-dsa.pem /tmp/nexusq-slh-dsa.pem

cd crates/nexusq-x509/interop/bouncycastle
mvn -q package dependency:build-classpath -Dmdep.outputFile=target/classpath.txt
java -cp "target/classes:$(cat target/classpath.txt)" VerifyCert /tmp/nexusq-ml-dsa65.pem
java -cp "target/classes:$(cat target/classpath.txt)" VerifyCert /tmp/nexusq-slh-dsa.pem
java -cp "target/classes:$(cat target/classpath.txt)" VerifyCert /tmp/nexusq-composite.pem
```

Observed on 2026-10-21: OpenSSL 3.5.9 verifies ML-DSA-65 and SLH-DSA roots; Bouncy Castle 1.86 verifies ML-DSA-65, SLH-DSA, and the experimental composite certificate. OpenSSL 3.5.9 does not recognize the draft composite public-key algorithm, so that profile is intentionally feature-gated and is not advertised as broadly interoperable.
