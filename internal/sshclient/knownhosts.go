// Package sshclient provides SSH connection establishment, authentication,
// trust-on-first-use host key verification, and interactive PTY sessions for
// Gravel.
package sshclient

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"

	"gravel/internal/sessionstore"
)

// HostKeyMismatchError is returned when a server presents a different host key
// than the one recorded during trust-on-first-use enrollment.
type HostKeyMismatchError struct {
	Addr       string
	Expected   string
	Actual     string
	ActualType string
}

func (e *HostKeyMismatchError) Error() string {
	return fmt.Sprintf("sshclient: host key mismatch for %s: recorded %s but server presented %s (%s)",
		e.Addr, e.Expected, e.Actual, e.ActualType)
}

// UnknownHostError is returned when Interactive mode is enabled and a host key
// has not been seen before. Callers should surface the fingerprint to the user
// and, on approval, invoke KnownHosts.Trust with the same fingerprint before
// retrying the connection.
type UnknownHostError struct {
	Addr        string
	Fingerprint string
	KeyType     string
}

func (e *UnknownHostError) Error() string {
	return fmt.Sprintf("sshclient: unknown host %s (fingerprint %s %s)", e.Addr, e.KeyType, e.Fingerprint)
}

// entrySep joins an address and the host key type into one map key. Addresses
// already contain ":", so the separator cannot collide with them.
const entrySep = "#"

// entryKey names one trusted key of one host: "addr#ssh-ed25519".
func entryKey(addr, keyType string) string { return addr + entrySep + keyType }

// splitEntryKey breaks an entry key back into its parts.
func splitEntryKey(k string) (addr, keyType string) {
	i := strings.LastIndex(k, entrySep)
	if i < 0 {
		return k, ""
	}
	return k[:i], k[i+len(entrySep):]
}

// KnownHosts records server fingerprints using trust-on-first-use (TOFU): the
// first key seen for an address is accepted and stored; later connections must
// match it exactly. When Interactive is true, unknown hosts return
// *UnknownHostError and require an explicit Trust call before proceeding.
//
// Keys are stored per (addr, key type) the way OpenSSH stores one line per
// algorithm: a server that offers both an RSA and an ED25519 host key - and
// negotiates a different one after a restart - must not look like a
// man-in-the-middle to a user who never approved the switch.
type KnownHosts struct {
	mu    sync.Mutex
	path  string
	hosts map[string]string // "addr#keyType" -> sha256 fingerprint
	// legacy holds records written by older Gravel builds, which stored one
	// bare fingerprint per address with no key type. They are re-keyed onto
	// the first handshake that proves the type, or accepted as a match for a
	// presented fingerprint of the same address, and disappear on the next
	// save.
	legacy map[string]string // addr -> sha256 fingerprint
	// OnNewHost, when set, is called with the addr of a host being enrolled.
	OnNewHost func(addr string)
	// Interactive makes first-time connections return UnknownHostError instead
	// of silently enrolling the key. The UI is expected to prompt the user and
	// call Trust on approval.
	Interactive bool
	// pending captures the last-observed error per (addr, key type) so the
	// Dial path can retrieve it after the ssh library has wrapped the error,
	// and so Trust can verify that the fingerprint the user approved is
	// exactly the one on the table - whether it was an unknown host or a
	// changed key.
	pending map[string]error
}

// NewKnownHosts returns a TOFU store backed by known_hosts.json inside dir.
func NewKnownHosts(dir string) *KnownHosts {
	return &KnownHosts{
		path:    filepath.Join(dir, "known_hosts.json"),
		hosts:   map[string]string{},
		legacy:  map[string]string{},
		pending: map[string]error{},
	}
}

// Load reads the recorded fingerprints. A missing file is treated as empty.
func (k *KnownHosts) Load() error {
	k.mu.Lock()
	defer k.mu.Unlock()

	data, err := os.ReadFile(k.path)
	if err != nil {
		if os.IsNotExist(err) {
			k.hosts = map[string]string{}
			k.legacy = map[string]string{}
			return nil
		}
		return err
	}
	m := map[string]string{}
	if len(trimWS(data)) > 0 {
		if err := json.Unmarshal(data, &m); err != nil {
			// Keep the unreadable file out of the way: a store that starts empty
			// and then saves would overwrite every fingerprint the user ever
			// confirmed, and the next connection would ask them to trust a host
			// they already had - which is exactly how a real key change stops
			// standing out.
			if moved := sessionstore.Quarantine(k.path); moved != "" {
				err = fmt.Errorf("%w (moved aside to %s)", err, moved)
			}
			return fmt.Errorf("sshclient: parse %s: %w", k.path, err)
		}
	}
	// Records written before keys became per-type carry a bare address. Keep
	// them in a side map instead of guessing a key type: a wrong guess would
	// either reject a good host or silently widen its trust.
	hosts := make(map[string]string, len(m))
	legacy := make(map[string]string)
	for key, fp := range m {
		addr, kt := splitEntryKey(key)
		if kt == "" {
			legacy[addr] = fp
			continue
		}
		hosts[key] = fp
	}
	k.hosts = hosts
	k.legacy = legacy
	return nil
}

func (k *KnownHosts) saveLocked() error {
	// Legacy records are not rewritten: they either get promoted by a
	// matching handshake (which writes the composite key) or are replaced by
	// an explicit Trust, and the next save leaves them out.
	if err := os.MkdirAll(filepath.Dir(k.path), 0o700); err != nil {
		return err
	}
	return sessionstore.WriteAtomic(k.path, k.marshalLocked())
}

// marshalLocked renders the store exactly as it is written: composite keys
// only, so a save flushes the legacy side map out of the file for good.
func (k *KnownHosts) marshalLocked() []byte {
	data, err := json.MarshalIndent(k.hosts, "", "  ")
	if err != nil {
		// A map of two strings cannot fail to marshal; return a valid empty
		// object rather than a half-written file.
		return []byte("{}")
	}
	return data
}

// Verify implements the TOFU check for the given address and remote key.
// First contact with a key type enrolls it (or, in Interactive mode, errors
// with UnknownHostError); a key already trusted for this exact type must match
// it, and a fingerprint recorded under another type still counts as seen for
// that address so a key rotation prompts the user instead of silently
// enrolling a stranger.
func (k *KnownHosts) Verify(addr string, remote net.Addr, key ssh.PublicKey) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.verifyLocked(addr, key)
}

// verifyLocked is the TOFU core with the store lock held: every branch both
// reads and mutates the maps, so unlocking to record a pending result would
// let two handshakes interleave and trust a key the user never saw.
func (k *KnownHosts) verifyLocked(addr string, key ssh.PublicKey) error {
	fp := ssh.FingerprintSHA256(key)
	kt := key.Type()

	if k.pending == nil {
		k.pending = map[string]error{}
	}
	if k.legacy == nil {
		k.legacy = map[string]string{}
	}
	ek := entryKey(addr, kt)
	if stored, seen := k.hosts[ek]; seen {
		if stored == fp {
			return nil
		}
		err := &HostKeyMismatchError{Addr: addr, Expected: stored, Actual: fp, ActualType: kt}
		k.pending[ek] = err
		return err
	}
	// A fingerprint the store already knows for this address under no type -
	// a record written before keys became per-type - is the same host on a
	// second algorithm: promote it instead of alarming the user twice.
	if legacyFP, ok := k.legacy[addr]; ok {
		if legacyFP == fp {
			k.hosts[ek] = fp
			delete(k.legacy, addr)
			return k.saveLocked()
		}
		// The old record does not match what is presented now. That is the
		// mismatch the user must see, not a brand-new host the UI would offer
		// to trust blind.
		err := &HostKeyMismatchError{Addr: addr, Expected: legacyFP, Actual: fp, ActualType: kt}
		k.pending[ek] = err
		return err
	}
	// The address was never enrolled under any type.
	if k.Interactive {
		err := &UnknownHostError{Addr: addr, Fingerprint: fp, KeyType: kt}
		k.pending[ek] = err
		return err
	}
	k.hosts[ek] = fp
	if err := k.saveLocked(); err != nil {
		return err
	}
	if k.OnNewHost != nil {
		k.OnNewHost(addr)
	}
	return nil
}

// Snapshot returns a copy of the stored host keys (composite "addr#type" key ->
// fingerprint). The pending, un-confirmed entries are not included. Nothing in
// the running app needs the whole map - the settings bundle that used to export
// it is gone - but the tests and the real-server harness read the store back
// through it to prove a key was recorded and can be changed.
func (k *KnownHosts) Snapshot() map[string]string {
	k.mu.Lock()
	defer k.mu.Unlock()
	out := make(map[string]string, len(k.hosts))
	for addr, fp := range k.hosts {
		out[addr] = fp
	}
	return out
}

// HostKeyCallback returns an ssh.HostKeyCallback bound to this store.
func (k *KnownHosts) HostKeyCallback() ssh.HostKeyCallback {
	return func(addr string, remote net.Addr, key ssh.PublicKey) error {
		return k.Verify(addr, remote, key)
	}
}

// PendingError returns the failure the last handshake for addr recorded - either
// the unknown-host prompt or the host key change - or nil when nothing is
// waiting. It is keyed on the address alone so both flows resolve through the
// same UI path, and it returns the error itself rather than a fingerprint, so
// the caller keeps the distinction: a changed key must reach the user as
// HostKeyMismatchError, not as a routine "new host, do you trust it?" prompt.
func (k *KnownHosts) PendingError(addr string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	for key, err := range k.pending {
		kaddr, _ := splitEntryKey(key)
		if kaddr == addr {
			return err
		}
	}
	return nil
}

// Trust records the given fingerprint for addr and clears the pending entry.
// It returns an error if the fingerprint does not match what was captured on
// the last failed connection attempt (guards against UI/user mismatch). When
// the pending entry was a host key change, the stored key is replaced - the
// same repair OpenSSH users make by hand with ssh-keygen -R, but only after
// the user confirmed this exact fingerprint.
func (k *KnownHosts) Trust(addr, fingerprint string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.pending == nil {
		k.pending = map[string]error{}
	}
	matched := false
	for key, err := range k.pending {
		kaddr, kt := splitEntryKey(key)
		if kaddr != addr {
			continue
		}
		switch e := err.(type) {
		case *UnknownHostError:
			if e.Fingerprint != fingerprint {
				continue
			}
		case *HostKeyMismatchError:
			if e.Actual != fingerprint {
				continue
			}
		default:
			continue
		}
		k.hosts[entryKey(addr, kt)] = fingerprint
		delete(k.pending, key)
		delete(k.legacy, addr)
		matched = true
	}
	if !matched {
		return fmt.Errorf("sshclient: no pending fingerprint for %s (or mismatch)", addr)
	}
	return k.saveLocked()
}

func trimWS(b []byte) []byte {
	start, end := 0, len(b)
	for start < end && isSpace(b[start]) {
		start++
	}
	for end > start && isSpace(b[end-1]) {
		end--
	}
	return b[start:end]
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r'
}
