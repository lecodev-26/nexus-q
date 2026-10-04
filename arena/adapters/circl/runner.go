package main

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

const (
	iterations = 20
	warmups    = 3
	message    = "nexusq-pqc-arena-v1"
)

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

func cpuFeatures() []string {
	v := os.Getenv("ARENA_CPU_FEATURES")
	if v == "" {
		return []string{}
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func emit(algorithm, parameterSet, operation string, latency time.Duration, sizes map[string]any) {
	latencyNS := float64(latency.Nanoseconds()) / float64(iterations)
	obj := map[string]any{
		"schema_version": 1,
		"run_id":         fmt.Sprintf("circl-%s-%s-%s", algorithm, parameterSet, operation),
		"implementation": map[string]any{
			"id": "circl", "version": envOr("CIRCL_VERSION", "1.6.4"), "commit": os.Getenv("CIRCL_COMMIT"),
		},
		"algorithm": map[string]string{"id": algorithm, "parameter_set": parameterSet},
		"operation": operation,
		"environment": map[string]any{
			"target":           envOr("ARENA_TARGET", runtime.GOARCH+"-"+runtime.GOOS),
			"os":               envOr("ARENA_OS", runtime.GOOS),
			"cpu":              envOr("ARENA_CPU", "unknown"),
			"cpu_features":     cpuFeatures(),
			"compiler":         "go",
			"compiler_version": runtime.Version(),
			"optimization":     envOr("ARENA_OPT", "unknown"),
			"harness_version":  "arena-v1",
		},
		"measurement": map[string]any{
			"iterations": iterations, "warmups": warmups,
			"measurement_timestamp_unix_ns": time.Now().UnixNano(),
			"latency_ns":                    latencyNS,
			"throughput_ops_s":              1_000_000_000.0 / latencyNS,
			"memory_bytes":                  nil,
			"measurement_method":            "time.Since mean wall-clock latency",
		},
		"sizes": sizes,
	}
	b, err := json.Marshal(obj)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(b))
}

func main() {
	kem := mlkem768.Scheme()
	for i := 0; i < warmups; i++ {
		pk, sk, err := kem.GenerateKeyPair()
		if err != nil {
			panic(err)
		}
		_ = pk
		_ = sk
	}
	start := time.Now()
	for i := 0; i < iterations; i++ {
		pk, sk, err := kem.GenerateKeyPair()
		if err != nil {
			panic(err)
		}
		_ = pk
		_ = sk
	}
	pk, sk, err := kem.GenerateKeyPair()
	if err != nil {
		panic(err)
	}
	emit("ml-kem", "768", "keygen", time.Since(start), map[string]any{"public_key_bytes": kem.PublicKeySize(), "secret_key_bytes": kem.PrivateKeySize(), "ciphertext_bytes": kem.CiphertextSize(), "signature_bytes": nil})

	var ct []byte
	for i := 0; i < warmups; i++ {
		c, ss, err := kem.Encapsulate(pk)
		if err != nil {
			panic(err)
		}
		_ = c
		_ = ss
	}
	start = time.Now()
	for i := 0; i < iterations; i++ {
		c, ss, err := kem.Encapsulate(pk)
		if err != nil {
			panic(err)
		}
		ct = c
		_ = ss
	}
	emit("ml-kem", "768", "encaps", time.Since(start), map[string]any{"public_key_bytes": kem.PublicKeySize(), "secret_key_bytes": kem.PrivateKeySize(), "ciphertext_bytes": len(ct), "signature_bytes": nil})
	for i := 0; i < warmups; i++ {
		ss, err := kem.Decapsulate(sk, ct)
		if err != nil {
			panic(err)
		}
		_ = ss
	}
	start = time.Now()
	for i := 0; i < iterations; i++ {
		ss, err := kem.Decapsulate(sk, ct)
		if err != nil {
			panic(err)
		}
		_ = ss
	}
	emit("ml-kem", "768", "decaps", time.Since(start), map[string]any{"public_key_bytes": kem.PublicKeySize(), "secret_key_bytes": kem.PrivateKeySize(), "ciphertext_bytes": len(ct), "signature_bytes": nil})

	sigScheme := mldsa65.Scheme()
	for i := 0; i < warmups; i++ {
		pk, sk, err := sigScheme.GenerateKey()
		if err != nil {
			panic(err)
		}
		_ = pk
		_ = sk
	}
	start = time.Now()
	for i := 0; i < iterations; i++ {
		pk, sk, err := sigScheme.GenerateKey()
		if err != nil {
			panic(err)
		}
		_ = pk
		_ = sk
	}
	sigPK, sigSK, err := sigScheme.GenerateKey()
	if err != nil {
		panic(err)
	}
	sig := sigScheme.Sign(sigSK, []byte(message), nil)
	emit("ml-dsa", "65", "keygen", time.Since(start), map[string]any{"public_key_bytes": sigScheme.PublicKeySize(), "secret_key_bytes": sigScheme.PrivateKeySize(), "ciphertext_bytes": nil, "signature_bytes": sigScheme.SignatureSize()})
	for i := 0; i < warmups; i++ {
		_ = sigScheme.Sign(sigSK, []byte(message), nil)
	}
	start = time.Now()
	for i := 0; i < iterations; i++ {
		_ = sigScheme.Sign(sigSK, []byte(message), nil)
	}
	emit("ml-dsa", "65", "sign", time.Since(start), map[string]any{"public_key_bytes": sigScheme.PublicKeySize(), "secret_key_bytes": sigScheme.PrivateKeySize(), "ciphertext_bytes": nil, "signature_bytes": sigScheme.SignatureSize()})
	for i := 0; i < warmups; i++ {
		if !sigScheme.Verify(sigPK, []byte(message), sig, nil) {
			panic("signature verification failed")
		}
	}
	start = time.Now()
	for i := 0; i < iterations; i++ {
		if !sigScheme.Verify(sigPK, []byte(message), sig, nil) {
			panic("signature verification failed")
		}
	}
	emit("ml-dsa", "65", "verify", time.Since(start), map[string]any{"public_key_bytes": sigScheme.PublicKeySize(), "secret_key_bytes": sigScheme.PrivateKeySize(), "ciphertext_bytes": nil, "signature_bytes": sigScheme.SignatureSize()})

}
