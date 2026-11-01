// Package sessionstore persists Graystone server profiles and known host keys
// to local JSON files. No credentials (passwords/passphrases) are ever written
// to disk; profiles only store connection metadata and key file paths.
package sessionstore

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// AuthKind identifies how a profile authenticates to a server.
type AuthKind string

const (
	// AuthPassword authenticates with a user-typed password (never stored).
	AuthPassword AuthKind = "password"
	// AuthKey authenticates with a private key file plus optional passphrase.
	AuthKey AuthKind = "key"
)

// Profile is a saved server connection. It intentionally contains no secret
// material: the password and key passphrase are supplied at connect time only.
// User is filled in for live sessions from the terminal login prompt; saved
// profiles leave it empty because no login name is stored.
type Profile struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Host    string   `json:"host"`
	Port    int      `json:"port"`
	User    string   `json:"user,omitempty"`
	Auth    AuthKind `json:"auth"`
	KeyPath string   `json:"key_path,omitempty"`
	// Order positions the profile in the UI list after the user dragged rows
	// into place. Zero means "never ranked": those entries follow the ranked
	// ones in name order, so a store that was never reordered keeps showing
	// the old alphabetical display.
	Order int `json:"order,omitempty"`
}

// Addr returns the "host:port" dial target for the profile.
func (p Profile) Addr() string {
	port := p.Port
	if port == 0 {
		port = 22
	}
	return fmt.Sprintf("%s:%d", p.Host, port)
}

// NewID returns a random hex identifier for a new profile.
func NewID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// Store manages profiles and tunnel definitions on disk, guarded by a mutex
// for concurrent access.
type Store struct {
	mu       sync.Mutex
	path     string
	profiles map[string]Profile
	// tunnelPath and tunnels mirror path/profiles for tunnels.json.
	// They share the same mutex: tunnel operations are infrequent enough
	// that a separate lock would add complexity without measurable benefit.
	tunnelPath string
	tunnels    map[string]TunnelDef
}

// NewStore returns a Store backed by sessions.json and tunnels.json inside dir.
func NewStore(dir string) *Store {
	return &Store{
		path:       filepath.Join(dir, "sessions.json"),
		profiles:   map[string]Profile{},
		tunnelPath: filepath.Join(dir, "tunnels.json"),
		tunnels:    map[string]TunnelDef{},
	}
}

// configDirName is the folder the app's data lives in - %APPDATA%\Graystone on
// Windows. Everything inside it (sessions, tunnels, trusted keys, the pinned
// settings and the WebView2 profile) travels with this one name, so the profile
// is pinned to it below rather than to the executable's file name.
const configDirName = "Graystone"

// DefaultDir returns the OS-specific config directory for Graystone, creating it
// if needed. On Windows this resolves under %APPDATA%.
func DefaultDir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return ensureDir(filepath.Join(base, configDirName))
}

// logPrefix begins the name of every per-launch log file. One file is created per
// start, so without pruning the folder grows for the lifetime of the install.
const logPrefix = "graystone-"

// PruneLogs deletes per-launch log files beyond the newest keep and reports how
// many went. Only plain files directly inside dir whose name starts with
// logPrefix and ends in .log are considered, so sessions.json, the known-hosts
// file and the WebView2 profile are never touched. keep below 1 is raised to 1:
// there is always at least the file this launch is writing.
func PruneLogs(dir string, keep int) (int, error) {
	if keep < 1 {
		keep = 1
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}
	type logFile struct {
		path    string
		modTime time.Time
	}
	var found []logFile
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".log") || !strings.HasPrefix(name, logPrefix) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		found = append(found, logFile{path: filepath.Join(dir, name), modTime: info.ModTime()})
	}
	if len(found) <= keep {
		return 0, nil
	}
	// Newest first, then delete the tail.
	sort.Slice(found, func(i, j int) bool { return found[i].modTime.After(found[j].modTime) })
	removed := 0
	for _, f := range found[keep:] {
		if err := os.Remove(f.path); err == nil {
			removed++
		}
	}
	return removed, nil
}

func ensureDir(p string) (string, error) {
	if err := os.MkdirAll(p, 0o700); err != nil {
		return "", err
	}
	return p, nil
}

// Load reads profiles from disk. A missing file is treated as an empty store.
func (s *Store) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			s.profiles = map[string]Profile{}
			return nil
		}
		return err
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		s.profiles = map[string]Profile{}
		return nil
	}
	var list []Profile
	if err := json.Unmarshal(data, &list); err != nil {
		// Start empty, but never over what could not be read: the first save
		// after a silent failure would otherwise write an almost-empty list over
		// the user's real profiles.
		if moved := Quarantine(s.path); moved != "" {
			err = fmt.Errorf("%w (moved aside to %s)", err, moved)
		}
		s.profiles = map[string]Profile{}
		return fmt.Errorf("sessionstore: parse %s: %w", s.path, err)
	}
	m := make(map[string]Profile, len(list))
	for _, p := range list {
		if p.ID == "" {
			p.ID = NewID()
		}
		m[p.ID] = p
	}
	s.profiles = m
	return nil
}

// save writes the current profiles atomically (temp file + rename). The caller
// must hold s.mu.
func (s *Store) save() error {
	list := s.sortedLocked()
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	return WriteAtomic(s.path, data)
}

// PutNamed inserts or updates a profile keyed by its name, so saving the same
// session name twice updates the existing row instead of piling up duplicates.
// The name is matched case-insensitively and trimmed; a blank name is rejected
// because it is the key the list and Load rely on.
func (s *Store) PutNamed(p Profile) (Profile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	p.Name = strings.TrimSpace(p.Name)
	if p.Name == "" {
		return p, fmt.Errorf("sessionstore: profile name is required")
	}
	if p.Auth == "" {
		p.Auth = AuthPassword
	}
	// Reuse the ID of an existing profile with the same name (any case), so a
	// second save of the same session updates its row.
	if id, existing, ok := s.matchByName(p.Name); ok {
		p.ID = id
		p.Order = existing.Order
		s.profiles[p.ID] = p
		if err := s.save(); err != nil {
			return p, err
		}
		return p, nil
	}
	if p.ID == "" {
		p.ID = NewID()
	}
	s.profiles[p.ID] = p
	if err := s.save(); err != nil {
		return p, err
	}
	return p, nil
}

// matchByName finds the stored profile a save should update: an exact name wins
// over a case-variant one, and among several case-variants the lowest ID is
// taken. The answer has to be deterministic because s.profiles is a map - with
// both "Web" and "web" stored, following the iteration order would update a
// different row on each run.
func (s *Store) matchByName(name string) (string, Profile, bool) {
	if id, p, ok := pickByName(s.profiles, name, true); ok {
		return id, p, true
	}
	return pickByName(s.profiles, name, false)
}

// pickByName returns the lowest-ID profile whose stored name equals name, exactly
// or - when exact is false - ignoring case. Names are trimmed the same way the
// save path trims them, so a trailing space cannot hide a duplicate.
func pickByName(profiles map[string]Profile, name string, exact bool) (string, Profile, bool) {
	bestID := ""
	var best Profile
	for id, existing := range profiles {
		stored := strings.TrimSpace(existing.Name)
		matched := stored == name
		if !matched && !exact {
			matched = strings.EqualFold(stored, name)
		}
		if !matched {
			continue
		}
		if bestID == "" || id < bestID {
			bestID, best = id, existing
		}
	}
	return bestID, best, bestID != ""
}

// Reorder ranks profiles to match the UI's drag-and-drop sequence: the ID at
// position i becomes the (i+1)-th row and every listed profile leaves the
// "never ranked" state. It is persisted like every other mutation.
func (s *Store) Reorder(ids []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, id := range ids {
		if p, ok := s.profiles[id]; ok {
			p.Order = i + 1
			s.profiles[id] = p
		}
	}
	return s.save()
}

// Get returns a profile by ID.
func (s *Store) Get(id string) (Profile, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.profiles[id]
	return p, ok
}

// ErrNotFound is returned when an operation names a profile that is not stored.
var ErrNotFound = errors.New("sessionstore: no such profile")

// Delete removes a profile and persists it. It returns ErrNotFound when the ID
// is unknown. A failed write is returned as an error and the row is put back in
// memory: a profile that vanishes here but survives in the file would come back
// on the next start, so reporting the delete as successful would promise a
// removal that never happened.
func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	old, ok := s.profiles[id]
	if !ok {
		return ErrNotFound
	}
	delete(s.profiles, id)
	if err := s.save(); err != nil {
		s.profiles[id] = old
		return err
	}
	return nil
}

// List returns all profiles sorted by name for stable UI display.
func (s *Store) List() []Profile {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sortedLocked()
}

func (s *Store) sortedLocked() []Profile {
	list := make([]Profile, 0, len(s.profiles))
	for _, p := range s.profiles {
		list = append(list, p)
	}
	sort.Slice(list, func(i, j int) bool {
		a, b := list[i], list[j]
		// Dragged rows lead in their assigned sequence; never-ranked rows
		// follow alphabetically, which is all a fresh store ever has.
		if (a.Order == 0) != (b.Order == 0) {
			return b.Order == 0
		}
		if a.Order != b.Order {
			return a.Order < b.Order
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.ID < b.ID
	})
	return list
}
