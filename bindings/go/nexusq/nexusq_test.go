package nexusq

import "testing"

func TestBackendInfoIsConsistent(t *testing.T) {
	info := CryptoBackendInfo()
	if info.Name == "" {
		t.Fatal("backend name must not be empty")
	}
	if info.NativeAvailable != (info.Name == "native-experimental") {
		t.Fatalf("inconsistent backend info: %+v", info)
	}
	if info.Experimental != info.NativeAvailable {
		t.Fatalf("inconsistent experimental flag: %+v", info)
	}
}
