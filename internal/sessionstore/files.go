package sessionstore

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// WriteAtomic writes data to path through a uniquely named temporary file in
// the same directory, so a reader never sees a half-written file.
//
// The temporary name is generated rather than fixed: two running instances
// saving the same store used to write the same "<path>.tmp" and could rename
// each other's half-written bytes into place. os.Rename replaces the target on
// Windows as well as on Unix, which is what makes the swap safe.
func WriteAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(name)
		return err
	}
	if err := os.Rename(name, path); err != nil {
		_ = os.Remove(name)
		return err
	}
	return nil
}

// Quarantine moves an unparseable data file aside and returns the name it moved
// to ("" when it could not be moved). It exists because a store that starts
// empty after a failed Load will happily write that emptiness back over the
// user's real data on the first save: profiles and trusted host keys are gone,
// and there is nothing left to recover. Moving the file first keeps the
// evidence and makes the overwrite impossible.
//
// The name is timestamped so a second bad file cannot destroy the first one's.
func Quarantine(path string) string {
	bad := fmt.Sprintf("%s.bad-%d", path, time.Now().Unix())
	if err := os.Rename(path, bad); err != nil {
		return ""
	}
	return bad
}
