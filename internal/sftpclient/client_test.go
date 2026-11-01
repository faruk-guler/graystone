package sftpclient

import (
	"bytes"
	"crypto/ed25519"
	crand "crypto/rand"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// startSFTPServer runs an in-process SSH server whose "sftp" subsystem is backed
// by an SFTP server operating on the real OS filesystem. It returns a dialed
// *ssh.Client ready for sftpclient.New.
func startSFTPServer(t *testing.T) *ssh.Client {
	t.Helper()

	_, hostPriv, err := ed25519.GenerateKey(crand.Reader)
	if err != nil {
		t.Fatalf("host key: %v", err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatalf("host signer: %v", err)
	}

	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if c.User() == "root" && string(pass) == "pw" {
				return nil, nil
			}
			return nil, fmt.Errorf("denied")
		},
	}
	cfg.AddHostKey(hostSigner)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			go serveSFTPSession(nc, cfg)
		}
	}()

	client, err := ssh.Dial("tcp", ln.Addr().String(), &ssh.ClientConfig{
		User:            "root",
		Auth:            []ssh.AuthMethod{ssh.Password("pw")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatalf("dial test server: %v", err)
	}
	t.Cleanup(func() { client.Close() })
	return client
}

func serveSFTPSession(nc net.Conn, cfg *ssh.ServerConfig) {
	sshConn, chans, reqs, err := ssh.NewServerConn(nc, cfg)
	if err != nil {
		return
	}
	defer sshConn.Close()
	go ssh.DiscardRequests(reqs)

	for newChan := range chans {
		if newChan.ChannelType() != "session" {
			newChan.Reject(ssh.UnknownChannelType, "no")
			continue
		}
		ch, requests, err := newChan.Accept()
		if err != nil {
			continue
		}
		go func(in <-chan *ssh.Request) {
			for req := range in {
				switch req.Type {
				case "subsystem":
					if bytes.Contains(req.Payload, []byte("sftp")) {
						req.Reply(true, nil)
						srv, err := sftp.NewServer(ch)
						if err != nil {
							return
						}
						_ = srv.Serve()
						ch.Close()
						return
					}
					req.Reply(false, nil)
				default:
					if req.WantReply {
						req.Reply(false, nil)
					}
				}
			}
		}(requests)
	}
}

func TestTouchCreatesEmptyFileAndRefusesOverwrite(t *testing.T) {
	root := filepath.ToSlash(t.TempDir())
	client := startSFTPServer(t)
	c, err := New(client)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer c.Close()

	p := root + "/fresh.txt"
	if err := c.Touch(p); err != nil {
		t.Fatalf("Touch: %v", err)
	}
	fi, err := c.Stat(p)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if fi.Size != 0 {
		t.Fatalf("new file size = %d, want 0", fi.Size)
	}
	if fi.IsDir {
		t.Fatal("new file must not be a directory")
	}

	// A second Touch has to fail rather than quietly truncate what is there.
	if err := c.Touch(p); err == nil {
		t.Fatal("Touch on an existing path must fail")
	}
	if _, err := c.Stat(p); err != nil {
		t.Fatalf("file disappeared after a refused Touch: %v", err)
	}
}

// TestWalkCollectsNestedFilesAndHonoursLimit covers the folder-download scan:
// every file below the root must appear exactly once with its full path, and a
// tree larger than the limit must fail rather than return a truncated list that
// would silently download only part of a folder.
func TestWalkCollectsNestedFilesAndHonoursLimit(t *testing.T) {
	root := filepath.ToSlash(t.TempDir())
	put := func(rel string) {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", rel, err)
		}
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}
	put("top.txt")
	put("a/one.txt")
	put("a/b/two.txt")
	put("c/three.txt")

	client := startSFTPServer(t)
	c, err := New(client)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer c.Close()

	got, err := c.Walk(root, 100)
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	want := map[string]bool{
		root + "/top.txt": true, root + "/a/one.txt": true,
		root + "/a/b/two.txt": true, root + "/c/three.txt": true,
	}
	if len(got) != len(want) {
		t.Fatalf("Walk returned %d paths, want %d: %v", len(got), len(want), got)
	}
	for _, p := range got {
		if !want[p] {
			t.Fatalf("Walk returned unexpected path %q", p)
		}
	}
	// Sorted output keeps the transfer queue in a predictable order.
	for i := 1; i < len(got); i++ {
		if got[i-1] > got[i] {
			t.Fatalf("Walk output not sorted: %q before %q", got[i-1], got[i])
		}
	}

	if _, err := c.Walk(root, 2); err == nil {
		t.Fatal("Walk must fail when the tree exceeds the limit")
	}

	// An empty directory is a valid, empty result - not an error.
	empty := filepath.ToSlash(t.TempDir())
	none, err := c.Walk(empty, 10)
	if err != nil {
		t.Fatalf("Walk on empty dir: %v", err)
	}
	if len(none) != 0 {
		t.Fatalf("Walk on empty dir returned %v", none)
	}
}

// TestWalkTreeReportsEveryDirectory pins the fix for folders that hold only
// empty sub-folders: Walk returns files alone, so mirroring a tree with it
// dropped the empty directories and left the copy incomplete. WalkTree returns
// them as paths relative to the walked root, root included as ".".
func TestWalkTreeReportsEveryDirectory(t *testing.T) {
	root := filepath.ToSlash(t.TempDir())
	put := func(rel string) {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", rel, err)
		}
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}
	put("top.txt")
	put("a/one.txt")
	// The three directories below carry no files at all. They are exactly what
	// the old Walk silently lost.
	for _, d := range []string{"empty", "a/emptynest", "a/emptynest/deeper"} {
		if err := os.MkdirAll(filepath.Join(root, filepath.FromSlash(d)), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}

	client := startSFTPServer(t)
	c, err := New(client)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer c.Close()

	files, dirs, err := c.WalkTree(root, 100)
	if err != nil {
		t.Fatalf("WalkTree: %v", err)
	}
	if len(files) != 2 {
		t.Fatalf("WalkTree files = %v, want the two written files", files)
	}
	want := map[string]bool{".": true, "a": true, "a/emptynest": true, "a/emptynest/deeper": true, "empty": true}
	got := make(map[string]bool, len(dirs))
	for _, d := range dirs {
		got[d] = true
	}
	for d := range want {
		if !got[d] {
			t.Fatalf("WalkTree lost directory %q (got %v)", d, dirs)
		}
	}
	if len(dirs) != len(want) {
		t.Fatalf("WalkTree dirs = %v, want %d entries", dirs, len(want))
	}
}

// TestWalkTreeOnEmptyFolderStillReturnsTheRoot keeps a fully empty pick usable:
// the caller creates the target from the returned directories, so the root must
// be in the list even when nothing else is.
func TestWalkTreeOnEmptyFolderStillReturnsTheRoot(t *testing.T) {
	root := filepath.ToSlash(t.TempDir())
	client := startSFTPServer(t)
	c, err := New(client)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer c.Close()

	files, dirs, err := c.WalkTree(root, 10)
	if err != nil {
		t.Fatalf("WalkTree on empty dir: %v", err)
	}
	if len(files) != 0 {
		t.Fatalf("WalkTree files = %v, want none", files)
	}
	if len(dirs) != 1 || dirs[0] != "." {
		t.Fatalf("WalkTree dirs = %v, want the root alone as %q", dirs, ".")
	}
}

// TestWalkTreeLimitBoundsFilesOnly documents the deliberate asymmetry: the cap
// exists to stop a folder download enqueueing tens of thousands of transfers,
// so it counts files. A deep tree of empty directories is a legitimate mirror
// target and must not trip it.
func TestWalkTreeLimitBoundsFilesOnly(t *testing.T) {
	root := filepath.ToSlash(t.TempDir())
	for _, d := range []string{"x/a/b/c", "y/d/e/f"} {
		if err := os.MkdirAll(filepath.Join(root, filepath.FromSlash(d)), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "one.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	client := startSFTPServer(t)
	c, err := New(client)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer c.Close()

	files, dirs, err := c.WalkTree(root, 1)
	if err != nil {
		t.Fatalf("WalkTree with a limit of one file: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("WalkTree files = %v, want exactly the one allowed", files)
	}
	// root, x, x/a, x/a/b, x/a/b/c, y, y/d, y/d/e, y/d/e/f - nine directories, all
	// of which survive a limit placed on the file count.
	if len(dirs) != 9 {
		t.Fatalf("WalkTree dirs = %v, want the whole 9-entry directory set despite the file limit", dirs)
	}
}

func TestSFTPOperations(t *testing.T) {
	root := t.TempDir()
	rootSlash := filepath.ToSlash(root)

	// Seed a couple of files via the local FS so List has something to see.
	if err := os.WriteFile(filepath.Join(root, "alpha.txt"), []byte("aaa"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	client := startSFTPServer(t)
	c, err := New(client)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer c.Close()

	// List
	entries, err := c.List(rootSlash)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 1 || entries[0].Name != "alpha.txt" {
		t.Fatalf("unexpected list: %+v", entries)
	}

	// Put a file on the server through the editor's write path, so the rename,
	// stat and read-back below have something real to work on. Chunked copies
	// with progress are the transfer queue's job and are tested there.
	content := strings.Repeat("x", 1000)
	remoteUpload := rootSlash + "/up.txt"
	if err := c.WriteFile(remoteUpload, []byte(content)); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Mkdir + nested file + recursive Remove
	sub := rootSlash + "/sub"
	if err := c.Mkdir(sub); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	if err := c.WriteFile(sub+"/nested.txt", []byte("nested")); err != nil {
		t.Fatalf("write nested: %v", err)
	}

	// Rename
	moved := rootSlash + "/moved.txt"
	if err := c.Rename(remoteUpload, moved); err != nil {
		t.Fatalf("Rename: %v", err)
	}
	if _, err := c.Stat(moved); err != nil {
		t.Fatalf("Stat moved: %v", err)
	}

	// Read it back through the same call the in-app editor uses.
	gotBytes, err := c.ReadFile(moved, 0)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(gotBytes) != content {
		t.Fatalf("read-back content mismatch: len=%d want=%d", len(gotBytes), len(content))
	}

	// Remove a file
	if err := c.Remove(moved); err != nil {
		t.Fatalf("Remove file: %v", err)
	}
	if _, err := c.Stat(moved); err == nil {
		t.Fatal("moved.txt should be gone")
	}

	// Remove a directory recursively
	if err := c.Remove(sub); err != nil {
		t.Fatalf("Remove dir recursive: %v", err)
	}
	if _, err := c.Stat(sub); err == nil {
		t.Fatal("sub dir should be gone")
	}
}

// TestMkdirAllBuildsTreeAndIgnoresExisting is the folder-upload primitive:
// mirroring a local tree creates every missing level in one call, and calling
// it again for a directory that already exists is not an error - the upload
// queue maps many files onto the same parent directories.
func TestMkdirAllBuildsTreeAndIgnoresExisting(t *testing.T) {
	root := filepath.ToSlash(t.TempDir())
	client := startSFTPServer(t)
	c, err := New(client)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer c.Close()

	deep := root + "/up/a/b/c"
	if err := c.MkdirAll(deep); err != nil {
		t.Fatalf("MkdirAll %s: %v", deep, err)
	}
	fi, err := c.Stat(deep)
	if err != nil || !fi.IsDir {
		t.Fatalf("deep directory missing after MkdirAll: %v %+v", err, fi)
	}
	if err := c.MkdirAll(deep); err != nil {
		t.Fatalf("MkdirAll over an existing directory must be silent, got %v", err)
	}
	if err := c.MkdirAll(root + "/up/a"); err != nil {
		t.Fatalf("MkdirAll over an existing ancestor: %v", err)
	}
}

// TestWriteReadFileRoundTrip is the editor's storage primitive: WriteFile
// replaces a file wholesale and ReadFile returns exactly those bytes, and the
// size cap plus the directory guard refuse the cases the editor must not load.
func TestWriteReadFileRoundTrip(t *testing.T) {
	root := filepath.ToSlash(t.TempDir())
	client := startSFTPServer(t)
	c, err := New(client)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer c.Close()

	p := root + "/note.txt"
	body := []byte("line one\nline two\n")
	if err := c.WriteFile(p, body); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	got, err := c.ReadFile(p, 1<<20)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("round trip mismatch: got %q want %q", got, body)
	}

	// A second write truncates rather than appends - the save semantics.
	if err := c.WriteFile(p, []byte("short")); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	got, _ = c.ReadFile(p, 0)
	if string(got) != "short" {
		t.Fatalf("rewrite did not truncate: %q", got)
	}

	// Over the cap is refused without reading the whole thing.
	if _, err := c.ReadFile(p, 3); err == nil || !strings.Contains(err.Error(), "edit limit") {
		t.Fatalf("expected the size cap to refuse, got %v", err)
	}
	// A directory is refused, not read as a file.
	if err := c.Mkdir(root + "/adir"); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if _, err := c.ReadFile(root+"/adir", 1<<20); err == nil || !strings.Contains(err.Error(), "directory") {
		t.Fatalf("expected directory refusal, got %v", err)
	}
}
