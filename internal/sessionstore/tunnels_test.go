package sessionstore

import (
	"os"
	"path/filepath"
	"testing"
)

func newTunnelStore(t *testing.T) *Store {
	t.Helper()
	return NewStore(t.TempDir())
}

func TestTunnelRoundTrip(t *testing.T) {
	s := newTunnelStore(t)
	if err := s.LoadTunnels(); err != nil {
		t.Fatalf("LoadTunnels: %v", err)
	}
	def, err := s.PutTunnel(TunnelDef{
		ProfileAddr: "10.0.0.1:22",
		Name:        "db",
		LocalPort:   5432,
		RemoteHost:  "db.internal",
		RemotePort:  5432,
		AutoStart:   true,
	})
	if err != nil {
		t.Fatalf("PutTunnel: %v", err)
	}
	if def.ID == "" {
		t.Fatal("PutTunnel must allocate an ID when none was given")
	}

	// Reload from disk and verify the data survived.
	s2 := NewStore(filepath.Dir(s.tunnelPath))
	if err := s2.LoadTunnels(); err != nil {
		t.Fatalf("reload LoadTunnels: %v", err)
	}
	list := s2.TunnelsForProfile("10.0.0.1:22")
	if len(list) != 1 {
		t.Fatalf("reload: got %d defs, want 1", len(list))
	}
	got := list[0]
	if got.Name != "db" || got.LocalPort != 5432 || got.RemoteHost != "db.internal" ||
		got.RemotePort != 5432 || !got.AutoStart {
		t.Fatalf("reload lost fields: %+v", got)
	}
	if got.ID != def.ID {
		t.Fatalf("reload ID = %q, want %q", got.ID, def.ID)
	}
}

func TestTunnelEmptyFileIsEmpty(t *testing.T) {
	s := newTunnelStore(t)
	// No file exists yet.
	if err := s.LoadTunnels(); err != nil {
		t.Fatalf("missing file: LoadTunnels = %v, want nil", err)
	}
	// Write an explicitly blank file (e.g. truncated by a failed save).
	if err := os.WriteFile(s.tunnelPath, []byte("  \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.LoadTunnels(); err != nil {
		t.Fatalf("blank file: LoadTunnels = %v, want nil", err)
	}
	if len(s.TunnelsForProfile("x:22")) != 0 {
		t.Fatal("blank file must load as empty")
	}
}

func TestTunnelCorruptFileIsQuarantined(t *testing.T) {
	s := newTunnelStore(t)
	// Write a file that cannot be parsed.
	if err := os.WriteFile(s.tunnelPath, []byte("{{{not json}}}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.LoadTunnels(); err == nil {
		t.Fatal("corrupt file: LoadTunnels = nil, want an error")
	}
	// The bad file must have been moved aside; tunnelPath no longer exists.
	if _, err := os.Stat(s.tunnelPath); err == nil {
		t.Fatal("corrupt file was not quarantined (tunnelPath still present)")
	}
	// At least one .bad-* file was created in the same directory.
	entries, _ := os.ReadDir(filepath.Dir(s.tunnelPath))
	found := false
	for _, e := range entries {
		if len(e.Name()) > len(filepath.Base(s.tunnelPath)) &&
			e.Name()[:len(filepath.Base(s.tunnelPath))] == filepath.Base(s.tunnelPath) {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("no quarantine file was created")
	}
	// After quarantine the store must be usable.
	if len(s.TunnelsForProfile("x:22")) != 0 {
		t.Fatal("corrupt store must start empty after quarantine")
	}
}

func TestPutTunnelUpdateKeepsID(t *testing.T) {
	s := newTunnelStore(t)
	_ = s.LoadTunnels()
	def1, err := s.PutTunnel(TunnelDef{ProfileAddr: "host:22", Name: "a", LocalPort: 1})
	if err != nil {
		t.Fatal(err)
	}
	// Update with the same ID.
	def1.Name = "b"
	def2, err := s.PutTunnel(def1)
	if err != nil {
		t.Fatal(err)
	}
	if def2.ID != def1.ID {
		t.Fatalf("update must keep the ID: %q vs %q", def2.ID, def1.ID)
	}
	list := s.TunnelsForProfile("host:22")
	if len(list) != 1 {
		t.Fatalf("update must not create a second row: %d rows", len(list))
	}
	if list[0].Name != "b" {
		t.Fatalf("update lost the new name: %+v", list[0])
	}
}

func TestDeleteTunnelByDefID(t *testing.T) {
	s := newTunnelStore(t)
	_ = s.LoadTunnels()
	def, _ := s.PutTunnel(TunnelDef{ProfileAddr: "host:22", Name: "x", LocalPort: 2})
	if err := s.DeleteTunnelByDefID(def.ID); err != nil {
		t.Fatalf("DeleteTunnelByDefID: %v", err)
	}
	if len(s.TunnelsForProfile("host:22")) != 0 {
		t.Fatal("deleted tunnel must be gone from the store")
	}
	// Deleting an empty or unknown ID is a no-op.
	if err := s.DeleteTunnelByDefID(""); err != nil {
		t.Fatalf("delete empty ID: %v", err)
	}
	if err := s.DeleteTunnelByDefID("unknown"); err != nil {
		t.Fatalf("delete unknown ID: %v", err)
	}
}

func TestTunnelsForProfileFiltersByAddr(t *testing.T) {
	s := newTunnelStore(t)
	_ = s.LoadTunnels()
	_, _ = s.PutTunnel(TunnelDef{ProfileAddr: "a:22", Name: "a1", LocalPort: 3001})
	_, _ = s.PutTunnel(TunnelDef{ProfileAddr: "b:22", Name: "b1", LocalPort: 3002})
	if list := s.TunnelsForProfile("a:22"); len(list) != 1 || list[0].Name != "a1" {
		t.Fatalf("a:22 filter: %+v", list)
	}
	if list := s.TunnelsForProfile("b:22"); len(list) != 1 || list[0].Name != "b1" {
		t.Fatalf("b:22 filter: %+v", list)
	}
	if list := s.TunnelsForProfile("c:22"); len(list) != 0 {
		t.Fatalf("c:22 should be empty: %+v", list)
	}
}

func TestTunnelsForDynamicForward(t *testing.T) {
	s := newTunnelStore(t)
	_ = s.LoadTunnels()
	// A dynamic (-D) tunnel has no remote host/port in the normal sense.
	def, err := s.PutTunnel(TunnelDef{ProfileAddr: "socks:22", Name: "SOCKS", LocalPort: 1080, Dynamic: true})
	if err != nil {
		t.Fatal(err)
	}
	list := s.TunnelsForProfile("socks:22")
	if len(list) != 1 {
		t.Fatalf("dynamic def not saved: %+v", list)
	}
	if !list[0].Dynamic {
		t.Fatal("Dynamic flag lost after round-trip")
	}
	if list[0].RemoteHost != "" || list[0].RemotePort != 0 {
		t.Fatalf("dynamic def should have empty remote fields: %+v", list[0])
	}
	_ = def
}
