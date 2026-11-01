package main

import (
	"strings"
	"testing"
)

// The file pane's three name fields - new folder, new file and rename - all mean
// "one entry, in the folder on screen". A name that addresses somewhere else is a
// typo, and honouring it would create or move a file the user never pointed at.

func TestRemoteBaseAcceptsPlainNames(t *testing.T) {
	for _, in := range []string{"notes.txt", "  spaced  ", "a b", "back\\slash", ".hidden", "..config", "v1.2.3", "Makefile"} {
		got, err := remoteBase(in)
		if err != nil {
			t.Errorf("remoteBase(%q): unexpected error %v", in, err)
			continue
		}
		if want := strings.TrimSpace(in); got != want {
			t.Errorf("remoteBase(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestRemoteBaseRefusesAnyOtherShape: "." and ".." name the folder itself and its
// parent, and a "/" turns the field into a path. Both would silently retarget the
// operation out of the directory being browsed.
func TestRemoteBaseRefusesAnyOtherShape(t *testing.T) {
	for _, in := range []string{"", "   ", ".", "..", "./x", "../passwd", "/etc/passwd", "a/b", "sub/dir/"} {
		if got, err := remoteBase(in); err == nil {
			t.Errorf("remoteBase(%q) = %q, want it refused", in, got)
		}
	}
}

func TestRemoteBaseRefusesNullByte(t *testing.T) {
	if _, err := remoteBase("ok\x00"); err == nil {
		t.Error("a name carrying a null byte must be refused")
	}
}
