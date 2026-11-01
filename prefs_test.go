package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The Settings sheet has exactly one persistence action now: pin the preferences
// to the config folder, beside the saved servers. These cover the whitelist that
// decides what may be pinned, the round trip, and the reset that has to clear the
// pinned copy too - a copy left behind would put the old settings back on the
// next start and undo the reset.

func TestSavePreferencesKeepsOnlyWhitelistedKeys(t *testing.T) {
	a := NewApp()
	a.configDir = t.TempDir()

	payload := `{"graystone.theme":"light","graystone.paneWidth":"640","graystone.secret":"hunter2","graystone.host":"10.0.0.1"}`
	if err := a.SavePreferences(payload); err != nil {
		t.Fatalf("SavePreferences: %v", err)
	}
	got := a.GetPreferences()
	if got["graystone.theme"] != "light" || got["graystone.paneWidth"] != "640" {
		t.Fatalf("known settings were not pinned: %+v", got)
	}
	for _, k := range []string{"graystone.secret", "graystone.host"} {
		if _, ok := got[k]; ok {
			t.Errorf("%s is outside the whitelist and must not be stored", k)
		}
	}
	// The file is the last word: what a webview smuggled in has to be gone from
	// disk as well as from the returned map.
	data, err := os.ReadFile(filepath.Join(a.configDir, "settings.json"))
	if err != nil {
		t.Fatalf("read pinned file: %v", err)
	}
	if strings.Contains(string(data), "graystone.secret") || strings.Contains(string(data), "hunter2") {
		t.Fatalf("pinned file holds a key that was never allowed: %s", data)
	}
}

// TestSavePreferencesRefusesJunk: a payload that is not an object, a value with
// a newline in it (the config file is read line-wise by nothing, but a log line
// or a hand-edited file would break) and an absurdly large request are all
// refused or dropped instead of being written.
func TestSavePreferencesRefusesJunk(t *testing.T) {
	a := NewApp()
	a.configDir = t.TempDir()

	if err := a.SavePreferences(`["not","an","object"]`); err == nil {
		t.Error("a payload that is not an object must be refused")
	}
	if err := a.SavePreferences(`{"graystone.theme":"dark\nevil"}`); err != nil {
		t.Fatalf("SavePreferences: %v", err)
	}
	if got := a.GetPreferences(); len(got) != 0 {
		t.Fatalf("a value carrying a newline was pinned: %+v", got)
	}
	if err := a.SavePreferences(`{"graystone.theme":"` + strings.Repeat("x", prefValueMax+1) + `"}`); err != nil {
		t.Fatalf("SavePreferences: %v", err)
	}
	if got := a.GetPreferences(); len(got) != 0 {
		t.Fatalf("an over-long value was pinned: %+v", got)
	}
	if err := a.SavePreferences(strings.Repeat(" ", maxPrefsPayload+1) + `{}`); err == nil {
		t.Error("an oversized payload must be refused outright")
	}
}

func TestEmptyPreferencesClearsThePinnedCopy(t *testing.T) {
	a := NewApp()
	a.configDir = t.TempDir()

	if err := a.SavePreferences(`{"graystone.theme":"light"}`); err != nil {
		t.Fatalf("SavePreferences: %v", err)
	}
	// A reset clears localStorage and has to clear this copy with it.
	if err := a.SavePreferences("{}"); err != nil {
		t.Fatalf("clearing the pinned copy: %v", err)
	}
	if got := a.GetPreferences(); len(got) != 0 {
		t.Fatalf("the pinned copy survived the clear: %+v", got)
	}
}

// TestPreferencesWithoutAConfigDir keeps both calls honest on the way up: the
// frontend asks for the pinned copy before startup has a directory to read it
// from, and a save with nowhere to write must say so rather than pretend.
func TestPreferencesWithoutAConfigDir(t *testing.T) {
	a := NewApp()
	if got := a.GetPreferences(); len(got) != 0 {
		t.Fatalf("expected an empty map, got %+v", got)
	}
	if err := a.SavePreferences(`{"graystone.theme":"light"}`); err == nil {
		t.Error("saving with no config directory must report the problem")
	}
}

// TestGetPreferencesMissingFileIsSilent is the first run: nothing has been
// pinned, which is not an error and not something to log.
func TestGetPreferencesMissingFileIsSilent(t *testing.T) {
	a := NewApp()
	a.configDir = t.TempDir()
	if got := a.GetPreferences(); len(got) != 0 {
		t.Fatalf("a first run must read as no pinned settings, got %+v", got)
	}
}

// TestPrefKeysCoverEveryPrefName keeps the whitelist and the list it is built
// from in step: a setting named in prefNames that never reaches prefKeys would be
// silently dropped by SavePreferences and lost on the next start.
func TestPrefKeysCoverEveryPrefName(t *testing.T) {
	if len(prefKeys) != len(prefNames) {
		t.Fatalf("prefKeys holds %d entries for %d names", len(prefKeys), len(prefNames))
	}
	for _, name := range prefNames {
		if !prefKeys[prefPrefix+name] {
			t.Errorf("%s%s is not in the whitelist the frontend is told about", prefPrefix, name)
		}
	}
}

// TestGetPreferencesQuarantinesAnUnreadableFile is the rule every config file
// follows: an unparseable copy is moved aside before anything can overwrite it,
// because the next save would otherwise write an empty map over the only copy.
func TestGetPreferencesQuarantinesAnUnreadableFile(t *testing.T) {
	a := NewApp()
	dir := t.TempDir()
	a.configDir = dir
	path := filepath.Join(dir, "settings.json")
	if err := os.WriteFile(path, []byte("{ not json"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	if got := a.GetPreferences(); len(got) != 0 {
		t.Fatalf("an unreadable file must read as no settings, got %+v", got)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("the unreadable file must be moved aside, not left to be overwritten")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	moved := 0
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "settings.json.bad-") {
			moved++
		}
	}
	if moved != 1 {
		t.Fatalf("expected one quarantined copy, found %d in %v", moved, entries)
	}
}
