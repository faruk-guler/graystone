package sshclient

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func mustSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return s
}

func TestKnownHostsTOFU(t *testing.T) {
	dir := t.TempDir()
	kh := NewKnownHosts(dir)
	if err := kh.Load(); err != nil {
		t.Fatalf("load: %v", err)
	}

	var enrolled []string
	kh.OnNewHost = func(addr string) { enrolled = append(enrolled, addr) }

	addr := "10.0.0.1:22"
	keyA := mustSigner(t).PublicKey()
	keyB := mustSigner(t).PublicKey()

	// First contact enrolls (TOFU) and returns nil.
	if err := kh.Verify(addr, nil, keyA); err != nil {
		t.Fatalf("first verify: %v", err)
	}
	if len(enrolled) != 1 {
		t.Fatalf("expected 1 enrollment, got %d", len(enrolled))
	}

	// Same key passes.
	if err := kh.Verify(addr, nil, keyA); err != nil {
		t.Fatalf("repeat verify: %v", err)
	}
	if len(enrolled) != 1 {
		t.Fatalf("expected no extra enrollment, got %d", len(enrolled))
	}

	// Different key triggers a mismatch error.
	err := kh.Verify(addr, nil, keyB)
	if err == nil {
		t.Fatal("expected mismatch error")
	}
	mismatch, ok := err.(*HostKeyMismatchError)
	if !ok {
		t.Fatalf("expected *HostKeyMismatchError, got %T", err)
	}
	if mismatch.Addr != addr {
		t.Fatalf("mismatch addr = %q, want %q", mismatch.Addr, addr)
	}

	// Persistence: a fresh store reloaded from disk keeps the enrollment.
	kh2 := NewKnownHosts(dir)
	if err := kh2.Load(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if err := kh2.Verify(addr, nil, keyA); err != nil {
		t.Fatalf("reloaded verify of known key: %v", err)
	}
	if err := kh2.Verify(addr, nil, keyB); err == nil {
		t.Fatal("reloaded store should still reject different key")
	}
}

func TestKnownHostsInteractiveTrust(t *testing.T) {
	dir := t.TempDir()
	kh := NewKnownHosts(dir)
	kh.Interactive = true
	if err := kh.Load(); err != nil {
		t.Fatalf("load: %v", err)
	}

	addr := "10.0.0.5:22"
	signer := mustSigner(t)
	err := kh.Verify(addr, nil, signer.PublicKey())
	if err == nil {
		t.Fatal("Interactive mode must not auto-enroll unknown hosts")
	}
	unk, ok := err.(*UnknownHostError)
	if !ok {
		t.Fatalf("expected *UnknownHostError, got %T", err)
	}
	if unk.Addr != addr || unk.Fingerprint == "" || unk.KeyType == "" {
		t.Fatalf("incomplete UnknownHostError: %+v", unk)
	}

	pending := kh.PendingError(addr)
	unk2, isUnknown := pending.(*UnknownHostError)
	if !isUnknown || unk2.Fingerprint != unk.Fingerprint || unk2.KeyType != unk.KeyType {
		t.Fatalf("PendingError must hand back the unknown-host failure, got %#v", pending)
	}
	fp := unk2.Fingerprint

	// Wrong fingerprint must be rejected.
	if err := kh.Trust(addr, "SHA256:not-the-right-one"); err == nil {
		t.Fatal("Trust with wrong fingerprint should fail")
	}

	// Correct fingerprint enrolls the host.
	if err := kh.Trust(addr, fp); err != nil {
		t.Fatalf("Trust: %v", err)
	}
	if still := kh.PendingError(addr); still != nil {
		t.Fatal("pending entry must be cleared after Trust")
	}
	if err := kh.Verify(addr, nil, signer.PublicKey()); err != nil {
		t.Fatalf("Verify after Trust should pass, got %v", err)
	}

	// Persistence: a reloaded store remembers the trusted fingerprint.
	kh2 := NewKnownHosts(dir)
	kh2.Interactive = true
	if err := kh2.Load(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if err := kh2.Verify(addr, nil, signer.PublicKey()); err != nil {
		t.Fatalf("reloaded Verify should pass, got %v", err)
	}
}

func mustRSAKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("rsa signer: %v", err)
	}
	return s.PublicKey()
}

// TestKnownHostsPerKeyType is the false-alarm fix: OpenSSH stores one line per
// algorithm, and so do we now. A server that offers both an RSA and an ED25519
// host key - and negotiates the other one after a restart - must connect
// cleanly, not scream man-in-the-middle at a key the user already trusted.
// A genuinely different key of the same type still mismatches.
func TestKnownHostsPerKeyType(t *testing.T) {
	dir := t.TempDir()
	kh := NewKnownHosts(dir)
	if err := kh.Load(); err != nil {
		t.Fatalf("load: %v", err)
	}

	addr := "10.0.0.9:22"
	ed := mustSigner(t).PublicKey()
	rsaKey := mustRSAKey(t)

	if err := kh.Verify(addr, nil, ed); err != nil {
		t.Fatalf("first ed25519 enroll: %v", err)
	}
	if err := kh.Verify(addr, nil, rsaKey); err != nil {
		t.Fatalf("second type (rsa) on a known host must enroll, got %v", err)
	}
	for _, key := range []ssh.PublicKey{ed, rsaKey} {
		if err := kh.Verify(addr, nil, key); err != nil {
			t.Fatalf("re-verify %s: %v", key.Type(), err)
		}
	}
	// Rotated key of the same type must still be refused.
	if err := kh.Verify(addr, nil, mustSigner(t).PublicKey()); err == nil {
		t.Fatal("expected mismatch for a different ed25519 key")
	}

	// Both types survive a reload: the file holds composite keys.
	kh2 := NewKnownHosts(dir)
	if err := kh2.Load(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	for _, key := range []ssh.PublicKey{ed, rsaKey} {
		if err := kh2.Verify(addr, nil, key); err != nil {
			t.Fatalf("reloaded verify %s: %v", key.Type(), err)
		}
	}
}

// TestKnownHostsLegacyMigration guards the upgrade path: stores written before
// keys became per-type hold one bare fingerprint per address. The same key
// reappearing must promote the record silently, and a different key must raise
// the mismatch dialog - never the first-time "do you trust this host?" prompt
// that would invite the user to accept a rotation blind.
func TestKnownHostsLegacyMigration(t *testing.T) {
	dir := t.TempDir()
	key := mustSigner(t).PublicKey()
	fp := ssh.FingerprintSHA256(key)
	data, err := json.Marshal(map[string]string{"10.0.0.10:22": fp})
	if err != nil {
		t.Fatalf("marshal legacy: %v", err)
	}
	path := filepath.Join(dir, "known_hosts.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write legacy: %v", err)
	}

	kh := NewKnownHosts(dir)
	kh.Interactive = true
	if err := kh.Load(); err != nil {
		t.Fatalf("load: %v", err)
	}

	// Same key as the legacy record: promoted, no prompt, no error.
	if err := kh.Verify("10.0.0.10:22", nil, key); err != nil {
		t.Fatalf("legacy same-key verify: %v", err)
	}
	if len(kh.legacy) != 0 {
		t.Fatalf("legacy record was not consumed: %v", kh.legacy)
	}

	// A different key for a host with a legacy record is a mismatch, and
	// Trust of the presented fingerprint replaces the stale entry.
	kh2 := NewKnownHosts(dir)
	kh2.Interactive = true
	if err := kh2.Load(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	other := mustSigner(t).PublicKey()
	err = kh2.Verify("10.0.0.10:22", nil, other)
	mm, ok := err.(*HostKeyMismatchError)
	if !ok {
		t.Fatalf("legacy foreign key: got %v, want *HostKeyMismatchError", err)
	}
	if mm.Expected != fp {
		t.Fatalf("mismatch should quote the legacy fingerprint, got %q", mm.Expected)
	}
	// Trusting a fingerprint nobody offered must be refused; the exact one on
	// the table replaces the record.
	if err := kh2.Trust("10.0.0.10:22", "SHA256:not-offered"); err == nil {
		t.Fatal("Trust must refuse a fingerprint the store never saw presented")
	}
	if err := kh2.Trust("10.0.0.10:22", mm.Actual); err != nil {
		t.Fatalf("Trust after mismatch: %v", err)
	}
	if err := kh2.Verify("10.0.0.10:22", nil, other); err != nil {
		t.Fatalf("verify after replacing the key: %v", err)
	}

	// The written file carries composite keys only.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	var persisted map[string]string
	if err := json.Unmarshal(raw, &persisted); err != nil {
		t.Fatalf("parse back: %v", err)
	}
	for k := range persisted {
		if !strings.Contains(k, entrySep) {
			t.Fatalf("legacy-format key %q survived a save", k)
		}
	}
}

// TestKnownHostsTrustAfterMismatch is the by-hand repair made safe: the stored
// key is only overwritten with the exact fingerprint the failing handshake
// recorded, so no UI flow can swap in an arbitrary key.
func TestKnownHostsTrustAfterMismatch(t *testing.T) {
	dir := t.TempDir()
	kh := NewKnownHosts(dir)
	if err := kh.Load(); err != nil {
		t.Fatalf("load: %v", err)
	}
	addr := "10.0.0.11:22"
	first := mustSigner(t).PublicKey()
	if err := kh.Verify(addr, nil, first); err != nil {
		t.Fatalf("enroll: %v", err)
	}

	second := mustSigner(t).PublicKey()
	if err := kh.Verify(addr, nil, second); err == nil {
		t.Fatal("rotated key must mismatch")
	}
	mm, isMismatch := kh.PendingError(addr).(*HostKeyMismatchError)
	if !isMismatch || mm.ActualType != second.Type() || mm.Actual != ssh.FingerprintSHA256(second) {
		t.Fatalf("a rotated key must stay a mismatch failure, got %#v", kh.PendingError(addr))
	}
	if err := kh.Trust(addr, mm.Actual); err != nil {
		t.Fatalf("Trust the changed key: %v", err)
	}
	if err := kh.Verify(addr, nil, second); err != nil {
		t.Fatalf("verify replaced key: %v", err)
	}
	if err := kh.Verify(addr, nil, first); err == nil {
		t.Fatal("the replaced key must no longer be trusted")
	}
}

// TestKnownHostsLoadMovesAnUnparseableFileAside is the security half of the same
// rule the profile store follows: a trust list that cannot be read must never be
// written back over. Starting empty is survivable - starting empty and then
// enrolling keys on top of the user's real history is how every host quietly
// becomes "new", until the user clicks Trust out of habit and a genuine key
// change stops standing out.
func TestKnownHostsLoadMovesAnUnparseableFileAside(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "known_hosts.json")
	const original = `{"10.0.0.1#ssh-ed25519":"SHA256:real",,}`
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	kh := NewKnownHosts(dir)
	err := kh.Load()
	if err == nil {
		t.Fatal("Load must report the broken file")
	}
	if !strings.Contains(err.Error(), "moved aside") {
		t.Errorf("err = %v, want it to say where the file went", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("the unreadable file must no longer sit at %s", path)
	}

	// A later enrollment writes a fresh file; the old bytes stay recoverable.
	// Trust only confirms a fingerprint a handshake already left pending, so the
	// non-interactive Verify is the path that actually saves here.
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("host key: %v", err)
	}
	pub, err := ssh.NewPublicKey(priv.Public())
	if err != nil {
		t.Fatalf("public key: %v", err)
	}
	kh.Interactive = false
	if err := kh.Verify("10.0.0.2:22", nil, pub); err != nil {
		t.Fatalf("Verify enrolling a new host: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	var preserved bool
	for _, e := range entries {
		if !strings.Contains(e.Name(), ".bad-") {
			continue
		}
		if got, rerr := os.ReadFile(filepath.Join(dir, e.Name())); rerr == nil && string(got) == original {
			preserved = true
		}
	}
	if !preserved {
		t.Fatal("the quarantined host key list was not preserved intact")
	}
}
