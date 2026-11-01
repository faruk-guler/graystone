package sessionstore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLoadMovesUnparseableFileAside pins the reason Load quarantines instead of
// just reporting: a store that starts empty and then saves would write that
// emptiness over the user's real server list. The bytes have to survive
// somewhere the next save cannot reach.
func TestLoadMovesUnparseableFileAside(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sessions.json")
	const original = `[{"id":"abc","name":"lost","host":"10.0.0.9","port":22,"auth":"password"},]`
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	s := NewStore(dir)
	err := s.Load()
	if err == nil {
		t.Fatal("Load must report the broken file")
	}
	if !strings.Contains(err.Error(), "moved aside") {
		t.Errorf("err = %v, want it to say where the file went", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("the unreadable file must no longer sit at %s: %v", path, err)
	}
	moved := filesWith(t, dir, ".bad-")
	if len(moved) != 1 {
		t.Fatalf("expected one quarantined file, got %v", moved)
	}
	if got, err := os.ReadFile(moved[0]); err != nil || string(got) != original {
		t.Fatalf("quarantined bytes changed: %q err=%v", got, err)
	}

	// The store is usable and its first save must not touch the evidence.
	if _, err := s.PutNamed(Profile{Name: "web", Host: "10.0.0.1"}); err != nil {
		t.Fatalf("PutNamed: %v", err)
	}
	if got, err := os.ReadFile(moved[0]); err != nil || string(got) != original {
		t.Fatal("a later save overwrote the quarantined file")
	}
	reloaded := NewStore(dir)
	if err := reloaded.Load(); err != nil {
		t.Fatalf("reload after quarantine: %v", err)
	}
	if list := reloaded.List(); len(list) != 1 || list[0].Name != "web" {
		t.Fatalf("unexpected list after quarantine: %+v", list)
	}
}

// TestWriteAtomicLeavesNoTempFile: the temp file must be renamed away, not
// littered through the config folder on the happy path.
func TestWriteAtomicLeavesNoTempFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "proxy.json")
	if err := WriteAtomic(path, []byte(`{"kind":"socks5"}`)); err != nil {
		t.Fatalf("WriteAtomic: %v", err)
	}
	if left := filesWith(t, dir, ".tmp-"); len(left) != 0 {
		t.Fatalf("temp files left behind: %v", left)
	}
	// Writing twice replaces rather than appends, and the second write used a
	// different temp name than the first.
	if err := WriteAtomic(path, []byte(`{"kind":"http"}`)); err != nil {
		t.Fatalf("second WriteAtomic: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(data) != `{"kind":"http"}` {
		t.Fatalf("content = %s, want the second write", data)
	}
}

// filesWith lists the entries in dir whose name contains needle, which is how
// both tests find a quarantined file (".bad-") or a stray temp file (".tmp-").
func filesWith(t *testing.T, dir, needle string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	var out []string
	for _, e := range entries {
		if strings.Contains(e.Name(), needle) {
			out = append(out, filepath.Join(dir, e.Name()))
		}
	}
	return out
}
