package sessionstore

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// TunnelDef is a persisted port-forward configuration keyed to a server
// (ProfileAddr = "host:port") so tunnels survive session closes and app
// restarts. A TunnelDef with no live session is in "stopped" state; it is
// auto-started when a new connection to that server opens.
// No secrets are stored: tunnel parameters are purely routing information.
type TunnelDef struct {
	// ID is the tunnels.json primary key; allocated by NewID on first persist.
	ID string `json:"id"`
	// ProfileAddr is the "host:port" of the SSH server this definition belongs
	// to; it is the grouping key used by TunnelsForProfile.
	ProfileAddr string `json:"profileAddr"`
	Name        string `json:"name"`
	LocalPort   int    `json:"localPort"`
	RemoteHost  string `json:"remoteHost"`
	RemotePort  int    `json:"remotePort"`
	Dynamic     bool   `json:"dynamic"`
	Remote      bool   `json:"remote"`
	BindAll     bool   `json:"bindAll"`
	AutoStart   bool   `json:"autoStart"`
}

// LoadTunnels reads tunnels.json into the store. A missing or blank file
// initialises an empty map so the first save never needs a special case.
// A corrupt file is quarantined before returning an error, mirroring the
// profile-load rule: an unparseable file must not be overwritten by the
// next save, because the evidence would be lost.
func (s *Store) LoadTunnels() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(s.tunnelPath)
	if err != nil {
		if os.IsNotExist(err) {
			s.tunnels = map[string]TunnelDef{}
			return nil
		}
		return err
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		s.tunnels = map[string]TunnelDef{}
		return nil
	}
	var list []TunnelDef
	if err := json.Unmarshal(data, &list); err != nil {
		if moved := Quarantine(s.tunnelPath); moved != "" {
			err = fmt.Errorf("%w (moved aside to %s)", err, moved)
		}
		s.tunnels = map[string]TunnelDef{}
		return fmt.Errorf("sessionstore: parse %s: %w", s.tunnelPath, err)
	}
	m := make(map[string]TunnelDef, len(list))
	for _, d := range list {
		if d.ID == "" {
			d.ID = NewID()
		}
		m[d.ID] = d
	}
	s.tunnels = m
	return nil
}

// saveTunnelsLocked persists the tunnels map atomically. The caller must hold
// s.mu (all public tunnel methods acquire the lock themselves, then call this).
// Definitions are sorted by ProfileAddr then LocalPort so the file stays stable
// across saves and a diff is readable.
func (s *Store) saveTunnelsLocked() error {
	list := make([]TunnelDef, 0, len(s.tunnels))
	for _, d := range s.tunnels {
		list = append(list, d)
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].ProfileAddr != list[j].ProfileAddr {
			return list[i].ProfileAddr < list[j].ProfileAddr
		}
		if list[i].LocalPort != list[j].LocalPort {
			return list[i].LocalPort < list[j].LocalPort
		}
		return list[i].ID < list[j].ID
	})
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.tunnelPath), 0o700); err != nil {
		return err
	}
	return WriteAtomic(s.tunnelPath, data)
}

// PutTunnel inserts or updates a tunnel definition and persists it. When def.ID
// is empty a new ID is allocated (first persist). It returns the stored
// definition so the caller can read back the allocated ID.
func (s *Store) PutTunnel(def TunnelDef) (TunnelDef, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if def.ID == "" {
		def.ID = NewID()
	}
	s.tunnels[def.ID] = def
	if err := s.saveTunnelsLocked(); err != nil {
		return def, err
	}
	return def, nil
}

// DeleteTunnelByDefID removes a tunnel definition and persists the change.
// An empty or unknown id is a no-op: deleting something that is already gone
// is not an error worth reporting.
func (s *Store) DeleteTunnelByDefID(id string) error {
	if id == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tunnels, id)
	return s.saveTunnelsLocked()
}

// TunnelsForProfile returns all tunnel definitions stored for profileAddr
// (the "host:port" SSH address). The result is a fresh slice; mutations do not
// affect the store.
func (s *Store) TunnelsForProfile(profileAddr string) []TunnelDef {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]TunnelDef, 0, 4)
	for _, d := range s.tunnels {
		if d.ProfileAddr == profileAddr {
			out = append(out, d)
		}
	}
	return out
}
