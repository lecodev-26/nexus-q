package nexusq

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const runtimeVersion = "4.1.1"

func runtimeBaseURL() string {
	if testBase := os.Getenv("NEXUSQ_TEST_RUNTIME_BASE_URL"); testBase != "" {
		return strings.TrimRight(testBase, "/") + "/"
	}
	return "https://github.com/lecodev-26/nexus-q/releases/download/v" + runtimeVersion + "/"
}

type runtimeAsset struct{ asset, local string }

func resolveRuntime() string {
	if override := os.Getenv("NEXUSQ_LIBRARY"); override != "" {
		return override
	}
	asset, err := selectRuntimeAsset()
	if err != nil {
		panic(err)
	}
	cacheRoot, err := os.UserCacheDir()
	if err != nil {
		panic(fmt.Errorf("resolve user cache directory: %w", err))
	}
	cache := filepath.Join(cacheRoot, "nexusq", runtimeVersion)
	if err := os.MkdirAll(cache, 0700); err != nil {
		panic(fmt.Errorf("create runtime cache: %w", err))
	}
	library := filepath.Join(cache, asset.local)
	digestFile := library + ".sha256"
	if bytes, err := os.ReadFile(library); err == nil {
		if digest, err := os.ReadFile(digestFile); err == nil && strings.EqualFold(strings.TrimSpace(string(digest)), digestHex(bytes)) {
			return library
		}
		// Remove incomplete/corrupt cache entries before atomic replacement; os.Rename
		// does not replace an existing destination on Windows.
		_ = os.Remove(library)
		_ = os.Remove(digestFile)
	}
	client := &http.Client{Timeout: 90 * time.Second}
	sums, err := fetch(client, runtimeBaseURL()+"NATIVE-RUNTIME-SHA256SUMS")
	if err != nil {
		panic(fmt.Errorf("download runtime checksums: %w", err))
	}
	expected := ""
	for _, line := range strings.Split(string(sums), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[len(fields)-1] == asset.asset {
			expected = strings.ToLower(fields[0])
			break
		}
	}
	if expected == "" {
		panic(fmt.Errorf("NEXUS-Q %s release has no checksum for %s", runtimeVersion, asset.asset))
	}
	binary, err := fetch(client, runtimeBaseURL()+asset.asset)
	if err != nil {
		panic(fmt.Errorf("download runtime %s: %w", asset.asset, err))
	}
	actual := digestHex(binary)
	if actual != expected {
		panic(fmt.Errorf("SHA-256 mismatch for NEXUS-Q runtime %s; refusing to load it", asset.asset))
	}
	temp, err := os.CreateTemp(cache, ".nexusq-runtime-*.download")
	if err != nil {
		panic(fmt.Errorf("create runtime temporary file: %w", err))
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	if _, err = temp.Write(binary); err == nil {
		err = temp.Sync()
	}
	closeErr := temp.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		panic(fmt.Errorf("write runtime cache: %w", err))
	}
	if err = os.Chmod(tempName, 0700); err != nil {
		panic(fmt.Errorf("set runtime permissions: %w", err))
	}
	if err = os.Rename(tempName, library); err != nil {
		panic(fmt.Errorf("install runtime cache: %w", err))
	}
	if err = os.WriteFile(digestFile, []byte(actual+"\n"), 0600); err != nil {
		panic(fmt.Errorf("write runtime digest cache: %w", err))
	}
	return library
}

func selectRuntimeAsset() (runtimeAsset, error) {
	switch runtime.GOOS + "/" + runtime.GOARCH {
	case "linux/amd64":
		if _, err := os.Stat("/lib/ld-musl-x86_64.so.1"); err == nil {
			return runtimeAsset{}, errors.New("NEXUS-Q prebuilt Linux runtimes require glibc, not musl/Alpine")
		}
		return runtimeAsset{"nexusq-sdk-runtime-linux-x64.so", "libnexusq.so"}, nil
	case "linux/arm64":
		if _, err := os.Stat("/lib/ld-musl-aarch64.so.1"); err == nil {
			return runtimeAsset{}, errors.New("NEXUS-Q prebuilt Linux runtimes require glibc, not musl/Alpine")
		}
		return runtimeAsset{"nexusq-sdk-runtime-linux-arm64.so", "libnexusq.so"}, nil
	case "darwin/arm64":
		return runtimeAsset{"nexusq-sdk-runtime-macos-arm64.dylib", "libnexusq.dylib"}, nil
	case "windows/amd64":
		return runtimeAsset{"nexusq-sdk-runtime-windows-x64.dll", "nexusq.dll"}, nil
	default:
		return runtimeAsset{}, fmt.Errorf("no prebuilt NEXUS-Q runtime for %s/%s; build a compatible runtime and set NEXUSQ_LIBRARY", runtime.GOOS, runtime.GOARCH)
	}
}

func fetch(client *http.Client, url string) ([]byte, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 512<<20))
}

func digestHex(bytes []byte) string { sum := sha256.Sum256(bytes); return hex.EncodeToString(sum[:]) }
