package main

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

const message = "nexusq-pqc-arena-v1"

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}
func count(name string, fallback int) int {
	v, err := strconv.Atoi(os.Getenv(name))
	if err != nil || v < 1 {
		return fallback
	}
	return v
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
func measure(warmups, iterations int, f func()) []int64 {
	for i := 0; i < warmups; i++ {
		f()
	}
	samples := make([]int64, iterations)
	for i := range samples {
		start := time.Now()
		f()
		samples[i] = time.Since(start).Nanoseconds()
		if samples[i] < 1 {
			samples[i] = 1
		}
	}
	return samples
}
func emit(algorithm, parameterSet, operation string, samples []int64, sizes map[string]any) {
	sorted := append([]int64(nil), samples...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	median := sorted[len(sorted)/2]
	if len(sorted)%2 == 0 {
		median = sorted[len(sorted)/2-1] + (sorted[len(sorted)/2]-sorted[len(sorted)/2-1])/2
	}
	p95 := sorted[(len(sorted)*95+99)/100-1]
	obj := map[string]any{
		"schema_version": 1, "run_id": fmt.Sprintf("circl-%s-%s-%s-%s", algorithm, parameterSet, operation, envOr("ARENA_RUN_ID", "local")),
		"implementation": map[string]any{"id": "circl", "version": envOr("CIRCL_VERSION", "1.6.4"), "commit": os.Getenv("CIRCL_COMMIT")},
		"algorithm":      map[string]string{"id": algorithm, "parameter_set": parameterSet}, "operation": operation,
		"environment": map[string]any{"target": envOr("ARENA_TARGET", runtime.GOARCH+"-"+runtime.GOOS), "os": envOr("ARENA_OS", runtime.GOOS), "cpu": envOr("ARENA_CPU", "unknown"), "cpu_features": cpuFeatures(), "compiler": "go", "compiler_version": runtime.Version(), "optimization": envOr("ARENA_OPT", "unknown"), "harness_version": "arena-v2"},
		"measurement": map[string]any{"iterations": len(samples), "warmups": count("ARENA_WARMUPS", 100), "measurement_timestamp_unix_ns": time.Now().UnixNano(), "latency_ns": median, "median_ns": median, "p95_ns": p95, "samples_ns": samples, "throughput_ops_s": 1e9 / float64(median), "memory_bytes": nil, "measurement_scope": "reference_implementation_operation", "comparison_contract": "fips_operation_v1", "measurement_method": "per-operation time.Since raw samples"},
		"sizes":       sizes,
	}
	b, err := json.Marshal(obj)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(b))
}
func main() {
	iterations, warmups := count("ARENA_ITERATIONS", 1000), count("ARENA_WARMUPS", 100)
	kem := mlkem768.Scheme()
	pk, sk, err := kem.GenerateKeyPair()
	var ct []byte
	var ss []byte
	keySizes := map[string]any{"public_key_bytes": kem.PublicKeySize(), "secret_key_bytes": kem.PrivateKeySize(), "ciphertext_bytes": kem.CiphertextSize(), "signature_bytes": nil}
	emit("ml-kem", "768", "keygen", measure(warmups, iterations, func() {
		pk, sk, err = kem.GenerateKeyPair()
		if err != nil {
			panic(err)
		}
		if _, err = pk.MarshalBinary(); err != nil {
			panic(err)
		}
		if _, err = sk.MarshalBinary(); err != nil {
			panic(err)
		}
	}), keySizes)
	pkBytes, err := pk.MarshalBinary()
	if err != nil {
		panic(err)
	}
	skBytes, err := sk.MarshalBinary()
	if err != nil {
		panic(err)
	}
	ctSizes := map[string]any{"public_key_bytes": kem.PublicKeySize(), "secret_key_bytes": kem.PrivateKeySize(), "ciphertext_bytes": kem.CiphertextSize(), "signature_bytes": nil}
	emit("ml-kem", "768", "encaps", measure(warmups, iterations, func() {
		var c []byte
		parsedPK, e := kem.UnmarshalBinaryPublicKey(pkBytes)
		if e != nil {
			panic(e)
		}
		c, ss, err = kem.Encapsulate(parsedPK)
		if err != nil {
			panic(err)
		}
		ct = c
	}), ctSizes)
	emit("ml-kem", "768", "decaps", measure(warmups, iterations, func() {
		parsedSK, e := kem.UnmarshalBinaryPrivateKey(skBytes)
		if e != nil {
			panic(e)
		}
		ss, err = kem.Decapsulate(parsedSK, ct)
		if err != nil {
			panic(err)
		}
		_ = ss
	}), ctSizes)
	sigScheme := mldsa65.Scheme()
	sigPK, sigSK, err := sigScheme.GenerateKey()
	var sig []byte
	sigSizes := map[string]any{"public_key_bytes": sigScheme.PublicKeySize(), "secret_key_bytes": sigScheme.PrivateKeySize(), "ciphertext_bytes": nil, "signature_bytes": sigScheme.SignatureSize()}
	emit("ml-dsa", "65", "keygen", measure(warmups, iterations, func() {
		sigPK, sigSK, err = sigScheme.GenerateKey()
		if err != nil {
			panic(err)
		}
		if _, err = sigPK.MarshalBinary(); err != nil {
			panic(err)
		}
		if _, err = sigSK.MarshalBinary(); err != nil {
			panic(err)
		}
	}), sigSizes)
	// Include parsing of serialized keys inside the timed operation, matching NEXUS-Q's byte-oriented contract.
	sigPKBytes, err := sigPK.MarshalBinary()
	if err != nil {
		panic(err)
	}
	sigSKBytes, err := sigSK.MarshalBinary()
	if err != nil {
		panic(err)
	}
	emit("ml-dsa", "65", "sign", measure(warmups, iterations, func() {
		parsedSK, e := sigScheme.UnmarshalBinaryPrivateKey(sigSKBytes)
		if e != nil {
			panic(e)
		}
		sig = sigScheme.Sign(parsedSK, []byte(message), nil)
	}), sigSizes)
	emit("ml-dsa", "65", "verify", measure(warmups, iterations, func() {
		parsedPK, e := sigScheme.UnmarshalBinaryPublicKey(sigPKBytes)
		if e != nil {
			panic(e)
		}
		if !sigScheme.Verify(parsedPK, []byte(message), sig, nil) {
			panic("signature verification failed")
		}
	}), sigSizes)
}
