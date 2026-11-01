package sessionstore

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func tempStore(t *testing.T) (*Store, string) {
	t.Helper()
	dir := t.TempDir()
	return NewStore(dir), dir
}

func TestSaveGetListRoundTrip(t *testing.T) {
	s, dir := tempStore(t)
	if err := s.Load(); err != nil {
		t.Fatalf("Load on empty: %v", err)
	}

	p, err := s.PutNamed(Profile{Name: "web", Host: "10.0.0.1", Port: 22, User: "root", Auth: AuthPassword})
	if err != nil {
		t.Fatalf("PutNamed: %v", err)
	}
	if p.ID == "" {
		t.Fatal("expected generated ID")
	}
	if _, err := s.PutNamed(Profile{Name: "db", Host: "10.0.0.2", Port: 2222, User: "admin", Auth: AuthKey, KeyPath: `C:\keys\id_ed25519`}); err != nil {
		t.Fatalf("PutNamed second: %v", err)
	}

	list := s.List()
	if len(list) != 2 {
		t.Fatalf("expected 2 profiles, got %d", len(list))
	}
	// Sorted by name: db before web.
	if list[0].Name != "db" || list[1].Name != "web" {
		t.Fatalf("unexpected order: %s, %s", list[0].Name, list[1].Name)
	}

	// Reload from a fresh store to prove persistence + no secret fields.
	s2 := NewStore(dir)
	if err := s2.Load(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	got, ok := s2.Get(p.ID)
	if !ok || got.Addr() != "10.0.0.1:22" {
		t.Fatalf("reload Get mismatch: %+v ok=%v", got, ok)
	}

	// Assert no credential VALUES are persisted. Note: the "auth" field may
	// legitimately hold the label "password" (a mode), so we only forbid
	// passphrase/secret material.
	data, err := os.ReadFile(filepath.Join(dir, "sessions.json"))
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	for _, banned := range []string{"passphrase", "secret", `"password":`} {
		if containsFold(string(data), banned) {
			t.Fatalf("sessions.json must not contain %q", banned)
		}
	}
}

// TestReorderPinsDraggedSequence proves the UI's drag-and-drop order survives a
// reload: ranked rows keep their sequence and a later-saved (unranked) profile
// lands after them by name rather than jumping back into alphabetical order.
func TestReorderPinsDraggedSequence(t *testing.T) {
	s, dir := tempStore(t)
	_ = s.Load()
	web, _ := s.PutNamed(Profile{Name: "web", Host: "h1"})
	db, _ := s.PutNamed(Profile{Name: "db", Host: "h2"})
	api, _ := s.PutNamed(Profile{Name: "api", Host: "h3"})

	// Alphabetical before any drag.
	if got := names(s.List()); got[0] != "api" || got[2] != "web" {
		t.Fatalf("pre-drag order = %v, want alphabetical", got)
	}

	// Drag web to the top, then db, then api.
	if err := s.Reorder([]string{web.ID, db.ID, api.ID}); err != nil {
		t.Fatalf("Reorder: %v", err)
	}
	if got := names(s.List()); got[0] != "web" || got[1] != "db" || got[2] != "api" {
		t.Fatalf("post-drag order = %v, want web, db, api", got)
	}

	// A profile saved after the drag stays unranked and sorts below them.
	if _, err := s.PutNamed(Profile{Name: "zeta", Host: "h4"}); err != nil {
		t.Fatalf("save after reorder: %v", err)
	}
	if got := names(s.List()); got[0] != "web" || got[3] != "zeta" {
		t.Fatalf("new profile misplaced: %v", got)
	}

	// Reload from disk: the ranked sequence must persist.
	s2 := NewStore(dir)
	if err := s2.Load(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got := names(s2.List()); got[0] != "web" || got[1] != "db" || got[2] != "api" {
		t.Fatalf("reloaded order = %v, want web, db, api", got)
	}
}

func names(ps []Profile) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.Name
	}
	return out
}

func TestDelete(t *testing.T) {
	s, _ := tempStore(t)
	_ = s.Load()
	p, _ := s.PutNamed(Profile{Name: "x", Host: "h"})
	if err := s.Delete(p.ID); err != nil {
		t.Fatalf("expected delete to succeed, got %v", err)
	}
	if err := s.Delete(p.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound on second delete, got %v", err)
	}
	if len(s.List()) != 0 {
		t.Fatal("expected empty list after delete")
	}
}

// TestDeleteKeepsRowWhenPersistFails pins the fix for the swallowed save error:
// a profile that could not be removed from the file must stay in memory, so no
// caller can report a deletion the next start would undo.
func TestDeleteKeepsRowWhenPersistFails(t *testing.T) {
	// sessions.json would have to live inside a regular file, so every write fails.
	blocker := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatalf("create blocker: %v", err)
	}
	s := NewStore(blocker)
	p, _ := s.PutNamed(Profile{Name: "x", Host: "h"})
	if _, ok := s.Get(p.ID); !ok {
		t.Fatal("PutNamed must keep the row in memory even when the write fails")
	}
	if err := s.Delete(p.ID); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("Delete = %v, want a persist error", err)
	}
	if _, ok := s.Get(p.ID); !ok {
		t.Fatal("failed Delete must restore the profile it could not persist")
	}
	if len(s.List()) != 1 {
		t.Fatalf("expected the profile to survive a failed Delete, got %d rows", len(s.List()))
	}
}

// TestPruneLogsKeepsNewest: a log file is written on every launch, so without
// pruning the config folder grows for the life of the install - and these files
// carry connection history, which is a reason to bound them rather than keep
// every one. Only the app's own per-launch logs may go.
func TestPruneLogsKeepsNewest(t *testing.T) {
	dir := t.TempDir()
	base := time.Now()
	logs := []string{
		"graystone-2026-09-30-090000.log",
		"graystone-2026-10-01-090000.log",
		"graystone-2026-10-02-090000.log",
		"graystone-2026-10-03-090000.log",
		"graystone-2026-10-04-090000.log",
	}
	for i, name := range logs {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
		stamp := base.Add(time.Duration(i) * time.Hour)
		if err := os.Chtimes(p, stamp, stamp); err != nil {
			t.Fatalf("chtimes %s: %v", name, err)
		}
	}
	neighbours := []string{"sessions.json", "known_hosts.json", "graystone-notes.txt", "notes.log"}
	for _, name := range neighbours {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("keep"), 0o600); err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
	}
	fakeDir := filepath.Join(dir, "graystone-2026-10-09-090000.log")
	if err := os.Mkdir(fakeDir, 0o700); err != nil {
		t.Fatalf("mkdir lookalike: %v", err)
	}

	removed, err := PruneLogs(dir, 2)
	if err != nil {
		t.Fatalf("PruneLogs: %v", err)
	}
	if removed != 3 {
		t.Fatalf("removed %d, want 3", removed)
	}
	for _, name := range []string{"graystone-2026-10-04-090000.log", "graystone-2026-10-03-090000.log"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("newest log %s was deleted: %v", name, err)
		}
	}
	for _, name := range []string{"graystone-2026-10-02-090000.log", "graystone-2026-10-01-090000.log", "graystone-2026-09-30-090000.log"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
			t.Fatalf("old log %s survived the prune", name)
		}
	}
	for _, name := range neighbours {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("%s must never be touched: %v", name, err)
		}
	}
	if fi, err := os.Stat(fakeDir); err != nil || !fi.IsDir() {
		t.Fatal("a folder named like a log must not be pruned")
	}
}

// TestPruneLogsAlwaysKeepsOne: the file this launch is writing must survive even
// if a caller asks for an impossible retention count.
func TestPruneLogsAlwaysKeepsOne(t *testing.T) {
	dir := t.TempDir()
	current := filepath.Join(dir, "graystone-2026-10-04-090000.log")
	if err := os.WriteFile(current, []byte("x"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	removed, err := PruneLogs(dir, 0)
	if err != nil {
		t.Fatalf("PruneLogs: %v", err)
	}
	if removed != 0 {
		t.Fatalf("removed %d, want 0", removed)
	}
	if _, err := os.Stat(current); err != nil {
		t.Fatalf("the only log was deleted: %v", err)
	}
}

func TestPruneLogsOnMissingDirReports(t *testing.T) {
	if _, err := PruneLogs(filepath.Join(t.TempDir(), "nope"), 5); err == nil {
		t.Fatal("PruneLogs should report an unreadable folder instead of failing silently")
	}
}

func containsFold(hay, needle string) bool {
	return len(hay) >= len(needle) && indexOf(lower(hay), lower(needle)) >= 0
}

func lower(s string) []byte {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return b
}

func indexOf(hay, needle []byte) int {
	for i := 0; i+len(needle) <= len(hay); i++ {
		match := true
		for j := range needle {
			if hay[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

// TestPutNamedDefaultsEmptyAuth covers the one store behaviour the import paths
// depend on and no other test exercises: every other PutNamed call in this file
// names an Auth explicitly, while the pasted-hosts import and a settings bundle
// both save profiles with no auth set. Those have to land as "password", not as
// an empty kind that authMethods then rejects as unknown.
func TestPutNamedDefaultsEmptyAuth(t *testing.T) {
	s, _ := tempStore(t)
	p, err := s.PutNamed(Profile{Name: "imported", Host: "10.0.0.1", Port: 22})
	if err != nil {
		t.Fatalf("PutNamed: %v", err)
	}
	if p.Auth != AuthPassword {
		t.Fatalf("Auth = %q, want the %q default", p.Auth, AuthPassword)
	}
}

// TestPutNamedPicksTheSameRowEveryTime covers a store that holds both "Web" and
// "web" - which an import or a hand-edited sessions.json can leave behind. The
// profiles live in a map, so a match that stops at the first hit would update a
// different row on each run; the rule is exact name first, then the lowest ID.
func TestPutNamedPicksTheSameRowEveryTime(t *testing.T) {
	s, _ := tempStore(t)
	if err := s.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	s.profiles["aaa"] = Profile{ID: "aaa", Name: "Web", Host: "10.0.0.1"}
	s.profiles["bbb"] = Profile{ID: "bbb", Name: "web", Host: "10.0.0.2"}

	// An exact match wins over a case-variant one.
	got, err := s.PutNamed(Profile{Name: "web", Host: "10.0.0.9"})
	if err != nil {
		t.Fatalf("PutNamed: %v", err)
	}
	if got.ID != "bbb" {
		t.Fatalf("ID = %q, want the exactly-named row bbb", got.ID)
	}

	// With no exact match the lowest ID is taken, and it stays that way over
	// repeated saves - 20 rounds so a dependence on map order cannot pass by luck.
	for i := 0; i < 20; i++ {
		got, err := s.PutNamed(Profile{Name: "WEB", Host: "10.0.0.5"})
		if err != nil {
			t.Fatalf("PutNamed round %d: %v", i, err)
		}
		if got.ID != "aaa" {
			t.Fatalf("round %d: ID = %q, want the lowest matching ID aaa", i, got.ID)
		}
	}
}
