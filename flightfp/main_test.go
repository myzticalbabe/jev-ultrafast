package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestShaFileMatchesStdlib(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "state.json")
	body := []byte(`{"url":"x"}`)
	if err := os.WriteFile(p, body, 0o644); err != nil {
		t.Fatal(err)
	}
	fp, err := shaFile(p)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	if fp.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("got %s want %s", fp.SHA256, hex.EncodeToString(sum[:]))
	}
	if fp.Size != int64(len(body)) {
		t.Fatalf("size %d want %d", fp.Size, len(body))
	}
}

func TestFingerprintDirSkipsSubdirs(t *testing.T) {
	d := t.TempDir()
	os.WriteFile(filepath.Join(d, "a.json"), []byte("{}"), 0o644)
	os.Mkdir(filepath.Join(d, "sub"), 0o755)
	os.WriteFile(filepath.Join(d, "sub", "b.json"), []byte("{}"), 0o644)
	got := fingerprintDir(d, ".json", 4)
	if len(got) != 1 || got[0].Name != "a.json" {
		t.Fatalf("got %+v", got)
	}
}
