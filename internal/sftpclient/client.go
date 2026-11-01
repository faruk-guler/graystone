package sftpclient

import (
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// Entry is a normalized directory/file listing for the UI file manager.
type Entry struct {
	Name    string
	Path    string
	IsDir   bool
	Size    int64
	Mode    os.FileMode
	ModTime time.Time
	Owner   string
	Group   string
}

// Client wraps an SFTP session that shares an established SSH connection.
type Client struct {
	sftp *sftp.Client
	ids  *idMaps
}

// New opens an SFTP subsystem over the given SSH client.
func New(sshClient *ssh.Client) (*Client, error) {
	if sshClient == nil {
		return nil, fmt.Errorf("sftpclient: nil ssh client")
	}
	// No packet-size override: pkg/sftp already defaults maxPacket to 32768, the
	// size every SFTP v3 server must answer, and its MaxPacket option refuses
	// anything larger because it is not portable across servers. The WAN
	// throughput lever lives on the caller side instead - see
	// transfer.copyChunkSize, where a buffer bigger than maxPacket makes
	// pkg/sftp split the request into concurrent sub-requests that overlap the
	// round trips.
	sc, err := sftp.NewClient(sshClient)
	if err != nil {
		return nil, fmt.Errorf("sftpclient: new sftp client: %w", err)
	}
	c := &Client{sftp: sc}
	c.ids = &idMaps{c: c} // back-pointer so the maps can read over this session
	return c, nil
}

// Close terminates the SFTP session (the underlying SSH client is unaffected).
func (c *Client) Close() error {
	if c == nil || c.sftp == nil {
		return nil
	}
	return c.sftp.Close()
}

// Raw returns the underlying *sftp.Client so callers (e.g. the transfer queue)
// can drive file operations directly.
func (c *Client) Raw() *sftp.Client { return c.sftp }

// Home returns the remote user's home directory. A freshly opened SFTP session
// starts in the authenticated user's home, so its working directory is exactly
// what a bare "cd" in the shell lands on. Falls back to "/" when the server
// does not answer, which keeps path resolution usable rather than empty.
func (c *Client) Home() string {
	wd, err := c.sftp.Getwd()
	if err != nil || wd == "" {
		return "/"
	}
	return wd
}

// joinRemote builds a POSIX-style remote path independent of the host OS.
func joinRemote(dir, name string) string {
	if dir == "/" {
		return "/" + name
	}
	return path.Join(dir, name)
}

// toEntry converts an os.FileInfo returned by the SFTP server, resolving the
// numeric owner/group carried in the raw attributes when they are available.
func (c *Client) toEntry(fi os.FileInfo, dir string) Entry {
	e := Entry{
		Name:    fi.Name(),
		Path:    joinRemote(dir, fi.Name()),
		IsDir:   fi.IsDir(),
		Size:    fi.Size(),
		Mode:    fi.Mode(),
		ModTime: fi.ModTime(),
	}
	if st, ok := fi.Sys().(*sftp.FileStat); ok && st != nil {
		e.Owner = c.ids.user(st.UID)
		e.Group = c.ids.group(st.GID)
	}
	return e
}

// List returns the entries of dir sorted with directories first, then by name.
func (c *Client) List(dir string) ([]Entry, error) {
	if dir == "" {
		dir = "/"
	}
	fis, err := c.sftp.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("sftpclient: list %s: %w", dir, err)
	}
	entries := make([]Entry, 0, len(fis))
	for _, fi := range fis {
		if fi == nil {
			continue
		}
		entries = append(entries, c.toEntry(fi, dir))
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].IsDir != entries[j].IsDir {
			return entries[i].IsDir
		}
		return entries[i].Name < entries[j].Name
	})
	return entries, nil
}

// Walk returns the path of every non-directory entry under dir, depth first, in
// sorted order. Symlinks are collected as plain files rather than descended
// into, so a link cycle cannot make the walk loop.
//
// limit bounds the result: "download folder" on something like / would
// otherwise enqueue an unbounded number of transfers.
func (c *Client) Walk(dir string, limit int) ([]string, error) {
	var out []string
	var walk func(string) error
	walk = func(d string) error {
		entries, err := c.List(d)
		if err != nil {
			return err
		}
		for _, e := range entries {
			if len(out) >= limit {
				return fmt.Errorf("sftpclient: walk %s: more than %d files", dir, limit)
			}
			if e.IsDir {
				if err := walk(e.Path); err != nil {
					return err
				}
				continue
			}
			out = append(out, e.Path)
		}
		return nil
	}
	if err := walk(dir); err != nil {
		return nil, err
	}
	sort.Strings(out)
	return out, nil
}

// WalkTree returns every non-directory path under dir AND every directory path
// (relative to dir, including dir itself as "."), so callers can recreate empty
// directories in the target. `limit` bounds only the file count, matching Walk's
// behavior: a tree of many empty subdirs is a legitimate download target, while
// a huge file list is the hazard the limit guards against.
//
// Relative directory paths use "/" as separator on all platforms.
func (c *Client) WalkTree(dir string, limit int) (files []string, dirs []string, err error) {
	base := strings.TrimRight(dir, "/")
	if base == "" {
		base = "/"
	}
	var walk func(d string) error
	walk = func(d string) error {
		entries, lerr := c.List(d)
		if lerr != nil {
			return lerr
		}
		// Record this directory (relative to base; "." for the root itself).
		rel := strings.TrimPrefix(d, base+"/")
		if rel == d {
			// d == base exactly (the root of the walk).
			rel = "."
		}
		dirs = append(dirs, rel)
		for _, e := range entries {
			if e.IsDir {
				if werr := walk(e.Path); werr != nil {
					return werr
				}
				continue
			}
			if len(files) >= limit {
				return fmt.Errorf("sftpclient: walk %s: more than %d files", dir, limit)
			}
			files = append(files, e.Path)
		}
		return nil
	}
	if err := walk(base); err != nil {
		return nil, nil, err
	}
	sort.Strings(files)
	return files, dirs, nil
}

// Stat returns metadata for a single remote path.
func (c *Client) Stat(p string) (Entry, error) {
	fi, err := c.sftp.Stat(p)
	if err != nil {
		return Entry{}, fmt.Errorf("sftpclient: stat %s: %w", p, err)
	}
	dir := path.Dir(p)
	e := c.toEntry(fi, dir)
	e.Path = p
	if e.Name == "." || e.Name == "/" {
		e.Name = fi.Name()
	}
	return e, nil
}

// Mkdir creates a single remote directory.
func (c *Client) Mkdir(p string) error {
	if err := c.sftp.Mkdir(p); err != nil {
		return fmt.Errorf("sftpclient: mkdir %s: %w", p, err)
	}
	return nil
}

// MkdirAll creates p and any missing parent directories, the way folder
// uploads need: mirroring a local tree means every level of the remote path
// may not exist yet on the first file. An existing directory is not an error.
func (c *Client) MkdirAll(p string) error {
	if err := c.sftp.MkdirAll(p); err != nil {
		return fmt.Errorf("sftpclient: mkdirall %s: %w", p, err)
	}
	return nil
}

// Touch creates an empty remote file with the server's default permissions. It
// refuses to touch a path that already exists, so the UI's "New file" action can
// never truncate something the user still needs (pkg/sftp's OpenFile takes no
// mode argument, unlike Create, which would truncate).
func (c *Client) Touch(p string) error {
	f, err := c.sftp.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL)
	if err != nil {
		return fmt.Errorf("sftpclient: create %s: %w", p, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("sftpclient: close %s after create: %w", p, err)
	}
	return nil
}

// Rename moves/renames a remote path.
func (c *Client) Rename(oldPath, newPath string) error {
	if err := c.sftp.Rename(oldPath, newPath); err != nil {
		return fmt.Errorf("sftpclient: rename %s -> %s: %w", oldPath, newPath, err)
	}
	return nil
}

// Chmod sets the permission bits of a remote path. Only the low nine bits
// (owner/group/world rwx) are sent; the caller masks anything else.
func (c *Client) Chmod(p string, mode os.FileMode) error {
	if err := c.sftp.Chmod(p, mode); err != nil {
		return fmt.Errorf("sftpclient: chmod %s: %w", p, err)
	}
	return nil
}

// Chown sets the owner and group of a remote path. A uid or gid of -1 leaves
// that field unchanged (the SFTP "no change" convention the OpenSSH server
// honours); changing either usually requires being root or owning the file.
func (c *Client) Chown(p string, uid, gid int) error {
	if err := c.sftp.Chown(p, uid, gid); err != nil {
		return fmt.Errorf("sftpclient: chown %s: %w", p, err)
	}
	return nil
}

// LookupUser and LookupGroup resolve an account name to its numeric id using
// the same /etc/passwd and /etc/group maps the display path reads, so chown can
// take a name typed by the user without executing anything on the server.
func (c *Client) LookupUser(name string) (int, bool)  { return c.ids.userID(name) }
func (c *Client) LookupGroup(name string) (int, bool) { return c.ids.groupID(name) }

// Remove deletes a file, or a directory recursively.
func (c *Client) Remove(p string) error {
	fi, err := c.sftp.Stat(p)
	if err != nil {
		return fmt.Errorf("sftpclient: stat %s: %w", p, err)
	}
	if !fi.IsDir() {
		if err := c.sftp.Remove(p); err != nil {
			return fmt.Errorf("sftpclient: remove %s: %w", p, err)
		}
		return nil
	}
	return c.removeDirRecursive(p)
}

func (c *Client) removeDirRecursive(dir string) error {
	walk := c.sftp.Walk(dir)
	var paths []string
	for walk.Step() {
		if walk.Err() != nil {
			return walk.Err()
		}
		p := walk.Path()
		if p == dir {
			continue
		}
		paths = append(paths, p)
	}
	// Remove deepest entries first, then the root directory itself.
	for i := len(paths) - 1; i >= 0; i-- {
		if err := c.sftp.Remove(paths[i]); err != nil {
			return fmt.Errorf("sftpclient: remove %s: %w", paths[i], err)
		}
	}
	return c.sftp.RemoveDirectory(dir)
}

// ReadFile returns the whole contents of a remote file, refusing anything
// larger than limit bytes (limit <= 0 means no cap). The in-app editor uses it
// with a modest cap so opening a huge or binary file fails with a clear message
// instead of dumping megabytes into the UI or hanging on the transfer.
func (c *Client) ReadFile(p string, limit int64) ([]byte, error) {
	fi, err := c.sftp.Stat(p)
	if err != nil {
		return nil, fmt.Errorf("sftpclient: stat %s: %w", p, err)
	}
	if fi.IsDir() {
		return nil, fmt.Errorf("sftpclient: %s is a directory", p)
	}
	if limit > 0 && fi.Size() > limit {
		return nil, fmt.Errorf("sftpclient: %s is %d bytes, over the %d byte edit limit", p, fi.Size(), limit)
	}
	f, err := c.sftp.Open(p)
	if err != nil {
		return nil, fmt.Errorf("sftpclient: open %s: %w", p, err)
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("sftpclient: read %s: %w", p, err)
	}
	return data, nil
}

// WriteFile replaces a remote file's contents wholesale (create + truncate),
// which is exactly the save semantics the editor wants: the text on screen is
// the whole file. The handle is closed explicitly so a write error surfaces
// rather than being swallowed by the deferred close.
func (c *Client) WriteFile(p string, data []byte) error {
	f, err := c.sftp.Create(p)
	if err != nil {
		return fmt.Errorf("sftpclient: create %s: %w", p, err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("sftpclient: write %s: %w", p, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("sftpclient: close %s: %w", p, err)
	}
	return nil
}
