package main

import "testing"

// TestParsePermOctal pins the chmod parser the permission editor feeds: three
// (or a leading-zero four) octal digits, masked to the nine rwx bits, with the
// invalid shapes refused rather than silently accepted.
func TestParsePermOctal(t *testing.T) {
	valid := map[string]uint32{
		"644":  0o644,
		"0644": 0o644,
		"755":  0o755,
		"0":    0o000,
		"000":  0o000,
		"777":  0o777,
		"1234": 0o234, // four digits: the leading special bit is masked off
	}
	for in, want := range valid {
		got, err := parsePermOctal(in)
		if err != nil {
			t.Errorf("parsePermOctal(%q) error: %v", in, err)
			continue
		}
		if uint32(got) != want {
			t.Errorf("parsePermOctal(%q) = %04o, want %04o", in, got, want)
		}
	}

	invalid := []string{"", "8", "99", "abc", "07777", "12345"}
	for _, in := range invalid {
		if _, err := parsePermOctal(in); err == nil {
			t.Errorf("parsePermOctal(%q) accepted an invalid mode", in)
		}
	}
}

// TestResolveIDNumericAndEmpty covers the two chown paths that need no server
// lookup: an empty field means "leave unchanged" (-1) and a plain number is
// taken as the id. The name-resolution branch is exercised against the live
// account maps elsewhere.
func TestResolveIDNumericAndEmpty(t *testing.T) {
	lookup := func(string) (int, bool) { return 0, false } // never called here
	if id, err := resolveID("", lookup, "user"); err != nil || id != -1 {
		t.Errorf("empty owner = (%d,%v), want (-1,nil)", id, err)
	}
	if id, err := resolveID(" 1000 ", lookup, "user"); err != nil || id != 1000 {
		t.Errorf("numeric owner = (%d,%v), want (1000,nil)", id, err)
	}
	// A non-numeric name with a lookup that finds nothing must error, not
	// silently become a no-op chown.
	if _, err := resolveID("ghost", lookup, "user"); err == nil {
		t.Error("unknown user name must be an error")
	}
}
