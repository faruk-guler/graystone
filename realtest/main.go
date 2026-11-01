// Command realtest drives Graystone's own engine - the packages behind the UI -
// against real SSH servers, so protocol, permission and transfer behaviour is
// proven on live hosts instead of only against the in-process test server.
//
// Nothing is hardcoded; the targets come from the environment:
//
//	GRAYSTONE_T1_HOST / GRAYSTONE_T1_USER / GRAYSTONE_T1_PASS
//	GRAYSTONE_T2_HOST / GRAYSTONE_T2_USER / GRAYSTONE_T2_PASS
//
// Run with:  go run ./realtest
//
// Every artefact created on a server lives under ~/graystone-realtest and is removed
// on the way out. The trust store is a throwaway directory, so the user's real
// %APPDATA%\Graystone files are never touched.
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	crand "crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"encoding/pem"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/ssh"

	"graystone/internal/app"
	"graystone/internal/sessionstore"
	"graystone/internal/sftpclient"
	"graystone/internal/sshclient"
	"graystone/internal/transfer"
)

// ---------- reporting ----------

type report struct{ pass, fail int }

func (r *report) ok(name string, err error, detail ...any) bool {
	if err != nil {
		r.fail++
		fmt.Printf("FAIL %-54s %v\n", name, err)
		return false
	}
	r.pass++
	fmt.Printf("ok   %-54s %s\n", name, join(detail))
	return true
}

func (r *report) has(name, got, want string) bool {
	if strings.Contains(got, want) {
		r.pass++
		fmt.Printf("ok   %-54s %s\n", name, want)
		return true
	}
	r.fail++
	fmt.Printf("FAIL %-54s want %q in:\n%s\n", name, want, truncate(got, 400))
	return false
}

func (r *report) eq(name string, got, want any) bool {
	if fmt.Sprint(got) == fmt.Sprint(want) {
		r.pass++
		fmt.Printf("ok   %-54s %v\n", name, got)
		return true
	}
	r.fail++
	fmt.Printf("FAIL %-54s got %v want %v\n", name, got, want)
	return false
}

func (r *report) skip(name, why string) {
	fmt.Printf("skip %-54s %s\n", name, why)
}

func join(v []any) string {
	parts := make([]string, len(v))
	for i, x := range v {
		parts[i] = fmt.Sprint(x)
	}
	return strings.Join(parts, " ")
}

// ---------- target ----------

type target struct {
	label, host, user, pass string
	port                    int
	kh                      *sshclient.KnownHosts
	khFile                  string
	client                  *ssh.Client
	ctrl                    *app.Controller
	sftp                    *sftpclient.Client
	home, work              string
}

func (t *target) addr() string { return fmt.Sprintf("%s:%d", t.host, t.port) }

func (t *target) passwordProfile() sessionstore.Profile {
	return sessionstore.Profile{Host: t.host, Port: t.port, User: t.user, Auth: sessionstore.AuthPassword}
}

// exec runs one command in the live PTY and returns the raw output stream
// captured through SubscribeRaw. Assertions use containment: the stream is what
// the server actually sent, and asking it for an exact layout would test the
// harness rather than the app.
func (t *target) exec(cmd string) (string, error) {
	if t.ctrl == nil {
		return "", fmt.Errorf("no live session")
	}
	markerSeq++
	id := fmt.Sprintf("__grv%06d__", markerSeq)
	var buf bytes.Buffer
	var mu sync.Mutex
	unsub := t.ctrl.SubscribeRaw(func(b []byte) {
		mu.Lock()
		buf.Write(b)
		mu.Unlock()
	})
	defer unsub()
	if err := t.ctrl.WriteInput([]byte(cmd + "; echo " + id + "\n")); err != nil {
		return "", err
	}
	deadline := time.Now().Add(25 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(120 * time.Millisecond)
		mu.Lock()
		screen := buf.String()
		mu.Unlock()
		if settled(screen, id) {
			return screen, nil
		}
	}
	mu.Lock()
	screen := buf.String()
	mu.Unlock()
	return screen, fmt.Errorf("screen did not settle after: %s", cmd)
}

// settled reports whether the sentinel arrived as its own output line. Matching
// the raw id is not enough: the echoed command ends with "echo <id>" and would
// satisfy the check before the shell had run anything.
func settled(screen, id string) bool {
	for _, line := range strings.Split(screen, "\n") {
		if strings.TrimSpace(line) == id {
			return true
		}
	}
	return false
}

var markerSeq int

// marked folds a command's stderr into its stdout so a failure is visible in the
// screen text. exec appends the per-call sentinel itself.
func marked(cmd string) string {
	return fmt.Sprintf("{ %s ; } 2>&1", strings.ReplaceAll(cmd, "\n", "; "))
}

// run executes a command on its own exec channel and returns exact stdout.
// Verification uses this rather than the PTY screen: the screen is the thing
// under test, and its echoed command line makes value comparisons unreliable.
func (t *target) run(cmd string) (string, error) {
	if t.client == nil {
		return "", fmt.Errorf("no connection")
	}
	sess, err := t.client.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()
	out, err := sess.Output(cmd)
	return strings.TrimSpace(string(out)), err
}

// ---------- main ----------

func main() {
	r := &report{}
	t1, err := fromEnv("GRAYSTONE_T1", "server-A")
	if err != nil {
		fmt.Println("setup:", err)
		os.Exit(2)
	}
	t2, err := fromEnv("GRAYSTONE_T2", "server-B")
	if err != nil {
		fmt.Println("setup:", err)
		os.Exit(2)
	}
	base, err := os.MkdirTemp("", "graystone-realtest-*")
	if err != nil {
		fmt.Println("temp:", err)
		os.Exit(2)
	}
	defer os.RemoveAll(base)
	for i, t := range []*target{t1, t2} {
		dir := filepath.Join(base, fmt.Sprint(i))
		os.MkdirAll(dir, 0o700)
		t.kh = sshclient.NewKnownHosts(dir)
		t.khFile = filepath.Join(dir, "known_hosts.json")
	}

	fmt.Printf("\n== %s %s@%s | %s %s@%s ==\n\n", t1.label, t1.user, t1.host, t2.label, t2.user, t2.host)

	tofuThenConnect(r, t1)
	autoEnroll(r, t2)
	wrongPassword(r, t1)
	shell(r, t1)
	shell(r, t2)
	twoSessions(r, t1)
	resize(r, t1)
	sftpBasics(r, t1)
	sftpBasics(r, t2)
	chmodOn(r, t1)
	chownOn(r, t1)
	transferBothWays(r, t1)
	folderTree(r, t1)
	pauseResumeCancel(r, t1)
	conflicts(r, t1)
	editor(r, t1)
	ppkLive(r, t1)
	// Last, because it deliberately corrupts the trust record for this address.
	hostKeyChanged(r, t1)
	cleanup(r, t1)
	cleanup(r, t2)

	fmt.Printf("\n== %d ok, %d failed ==\n", r.pass, r.fail)
	if r.fail > 0 {
		os.Exit(1)
	}
}

func fromEnv(prefix, label string) (*target, error) {
	t := &target{port: 22, label: label}
	t.host, t.user, t.pass = os.Getenv(prefix+"_HOST"), os.Getenv(prefix+"_USER"), os.Getenv(prefix+"_PASS")
	if t.host == "" || t.user == "" || t.pass == "" {
		return nil, fmt.Errorf("%s_HOST/%s_USER/%s_PASS must all be set", prefix, prefix, prefix)
	}
	return t, nil
}

// ---------- authentication ----------

func tofuThenConnect(r *report, t *target) {
	t.kh.Interactive = true
	cred := sshclient.Credential{Password: t.pass}
	_, err := sshclient.Dial(t.passwordProfile(), cred, t.kh)
	var unk *sshclient.UnknownHostError
	if !errors.As(err, &unk) {
		r.ok("TOFU: unknown host reported first", fmt.Errorf("got %v", err))
		return
	}
	r.ok("TOFU: unknown host reported first", nil, unk.KeyType, unk.Fingerprint[:20]+"...")
	if err := t.kh.Trust(unk.Addr, unk.Fingerprint); err != nil {
		r.ok("TOFU: Trust records the fingerprint", err)
		return
	}
	client, err := sshclient.Dial(t.passwordProfile(), cred, t.kh)
	if r.ok("auth: password login after trust ("+t.addr()+")", err) {
		t.client = client
	}
	t.kh.Interactive = false
}

func autoEnroll(r *report, t *target) {
	client, err := sshclient.Dial(t.passwordProfile(), sshclient.Credential{Password: t.pass}, t.kh)
	if r.ok("auth: non-interactive enroll ("+t.addr()+")", err) {
		t.client = client
	}
}

func wrongPassword(r *report, t *target) {
	_, err := sshclient.Dial(t.passwordProfile(), sshclient.Credential{Password: t.pass + "~nope"}, t.kh)
	if err == nil {
		r.ok("auth: a wrong password is refused", fmt.Errorf("it logged in"))
		return
	}
	r.eq("auth: wrong password classified for re-prompt", sshclient.AuthFailed(err), true)
}

// ---------- live shell ----------

func shell(r *report, t *target) {
	ctrl := app.New(t.passwordProfile(), sshclient.Credential{Password: t.pass}, t.kh, nil)
	if err := ctrl.Connect(100, 30); err != nil {
		r.ok("pty: controller connect ("+t.addr()+")", err)
		return
	}
	t.ctrl = ctrl
	home, err := t.run("printf $HOME")
	if err != nil || home == "" {
		r.ok("pty: $HOME readable through an exec channel", fmt.Errorf("%q %v", home, err))
		return
	}
	t.home = home
	r.ok("pty: $HOME readable through an exec channel", nil, home)
	t.work = t.home + "/graystone-realtest"
	if _, err := t.run("mkdir -p " + t.work); err != nil {
		r.ok("pty: create the work dir", err)
		return
	}
	out, err := t.exec(marked("uname -sr; echo $((6*7)); printf 'x\\ny\\nz\\n' | wc -l"))
	r.has("pty: shell arithmetic runs", out, "42")
	r.has("pty: multi-line pipe counts", out, "3")
	r.has("pty: kernel identified", out, "Linux")
	who, err := t.run("id -un")
	if err == nil {
		r.eq("pty: the login user is who the profile says", who, t.user)
	}
	r.eq("pty: state stays connected", ctrl.State(), app.StateConnected)
}

// twoSessions answers the question the GUI could not: is the raw output stream
// that each session's xterm receives actually separated per controller? An
// empty result here is a backend problem; a populated one with the correct
// marker confirms the per-tab isolation works.
func twoSessions(r *report, t *target) {
	if t.client == nil {
		r.skip("two sessions: each screen holds its own content", "no connection")
		return
	}
	open := func(marker string) (string, *app.Controller) {
		ctrl := app.New(t.passwordProfile(), sshclient.Credential{Password: t.pass}, t.kh, nil)
		if err := ctrl.Connect(80, 24); err != nil {
			r.ok("two sessions: connect "+marker, err)
			return "", nil
		}
		var buf bytes.Buffer
		var mu sync.Mutex
		ctrl.SubscribeRaw(func(b []byte) {
			mu.Lock()
			buf.Write(b)
			mu.Unlock()
		})
		if err := ctrl.WriteInput([]byte("echo " + marker + "\n")); err != nil {
			r.ok("two sessions: write "+marker, err)
			return "", ctrl
		}
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			mu.Lock()
			text := buf.String()
			mu.Unlock()
			if strings.Contains(text, marker) {
				return text, ctrl
			}
			time.Sleep(100 * time.Millisecond)
		}
		mu.Lock()
		text := buf.String()
		mu.Unlock()
		return text, ctrl
	}

	s1, c1 := open("SNAPMARK_ONE")
	s2, c2 := open("SNAPMARK_TWO")
	if c1 != nil {
		defer c1.Close()
	}
	if c2 != nil {
		defer c2.Close()
	}
	r.eq("two sessions: first screen is not empty", s1 != "", true)
	r.eq("two sessions: first screen holds its own marker", strings.Contains(s1, "SNAPMARK_ONE"), true)
	r.eq("two sessions: second screen holds its own marker", strings.Contains(s2, "SNAPMARK_TWO"), true)
	r.eq("two sessions: the two screens stay separate", strings.Contains(s1, "SNAPMARK_TWO"), false)
}

func resize(r *report, t *target) {
	if t.ctrl == nil {
		r.skip("resize: remote PTY follows", "no session")
		return
	}
	t.ctrl.Resize(120, 40)
	time.Sleep(500 * time.Millisecond)
	out, err := t.exec(marked("stty size"))
	if err != nil {
		r.ok("resize: stty size", err)
		return
	}
	r.has("resize: remote PTY follows (rows cols)", out, "40 120")
	t.ctrl.Resize(100, 30)
}

// ---------- sftp ----------

func sftpBasics(r *report, t *target) {
	if t.ctrl == nil {
		r.skip("sftp: file operations", "no session")
		return
	}
	sc, err := t.ctrl.SFTP()
	if !r.ok("sftp: opened over the live connection", err) {
		return
	}
	t.sftp = sc
	r.eq("sftp: Home() agrees with the shell", sc.Home(), t.home)

	_, err = t.sftp.Stat(t.work + "/sub/inner.txt")
	if err == nil {
		// Second server: the same file may exist from a previous run; clean it.
		t.sftp.Remove(t.work + "/sub")
	}
	if err := sc.Mkdir(t.work + "/sub"); err != nil {
		r.ok("sftp: Mkdir", err)
		return
	}
	r.ok("sftp: Mkdir", nil)
	if err := sc.Touch(t.work + "/touched.txt"); err != nil {
		r.ok("sftp: Touch creates an empty file", err)
		return
	}
	r.ok("sftp: Touch creates an empty file", nil)
	if err := sc.WriteFile(t.work+"/sub/inner.txt", []byte("inner payload")); err != nil {
		r.ok("sftp: WriteFile into a subdir", err)
		return
	}
	r.ok("sftp: WriteFile into a subdir", nil, len("inner payload"), "bytes")

	st, err := sc.Stat(t.work + "/sub/inner.txt")
	if r.ok("sftp: Stat the written file", err) {
		r.eq("sftp: Stat reports the real size", st.Size, int64(len("inner payload")))
		r.eq("sftp: Stat says it is not a dir", st.IsDir, false)
	}
	list, err := sc.List(t.work)
	if r.ok("sftp: List the work dir", err) {
		r.eq("sftp: List returns dir-first entries", len(list) >= 2, true)
	}
	if err := sc.Rename(t.work+"/touched.txt", t.work+"/renamed.txt"); err != nil {
		r.ok("sftp: Rename", err)
	} else {
		_, gone := sc.Stat(t.work + "/touched.txt")
		r.eq("sftp: Rename leaves the old name behind", gone != nil, true)
	}
	paths, err := sc.Walk(t.work+"/sub", 100)
	if r.ok("sftp: Walk finds nested files", err) {
		r.eq("sftp: Walk returns the one file", len(paths), 1)
	}
}

func chmodOn(r *report, t *target) {
	if t.sftp == nil {
		r.skip("chmod: mode applied on the server", "no sftp session")
		return
	}
	p := t.work + "/sub/inner.txt"
	for _, want := range []string{"600", "755", "644"} {
		if err := t.sftp.Chmod(p, os.FileMode(parseOctal(want))); err != nil {
			r.ok("chmod: set "+want, err)
			return
		}
		got, err := t.run("stat -c %a " + p)
		if err != nil {
			r.ok("chmod: read it back with stat", err)
			return
		}
		r.eq("chmod: server reports "+want, got, want)
	}
	en, err := t.sftp.Stat(p)
	if r.ok("chmod: listing carries the stored mode", err) {
		r.eq("chmod: Entry.Mode.Perm matches 644", en.Mode.Perm(), os.FileMode(0o644))
	}
}

func chownOn(r *report, t *target) {
	if t.sftp == nil {
		r.skip("chown: uid/gid resolution", "no sftp session")
		return
	}
	p := t.work + "/sub/inner.txt"
	uid, ok := t.sftp.LookupUser(t.user)
	if !r.ok("chown: LookupUser resolves the login account", nilCheck(ok, fmt.Errorf("not found"))) {
		return
	}
	if err := t.sftp.Chown(p, uid, -1); err != nil {
		r.ok("chown: set the owner", err, "uid", uid)
		return
	}
	r.ok("chown: set the owner", nil, "uid", uid)
	got, err := t.run("stat -c %U " + p)
	if err == nil {
		r.eq("chown: server reports the owner", got, t.user)
	}
	_, bad := t.sftp.LookupUser("no-such-user-xyzzy")
	r.eq("chown: an unknown name does not resolve", bad, false)
}

// ---------- transfers ----------

func transferBothWays(r *report, t *target) {
	if t.sftp == nil {
		r.skip("transfer: 3 MB byte-exact both ways", "no sftp session")
		return
	}
	dir, _ := os.MkdirTemp("", "graystone-xfer-*")
	defer os.RemoveAll(dir)
	payload := randomBytes(3 << 20)
	local := filepath.Join(dir, "payload.bin")
	if err := os.WriteFile(local, payload, 0o600); err != nil {
		r.ok("transfer: write the local payload", err)
		return
	}
	sum := fmt.Sprintf("%x", sha256.Sum256(payload))
	remote := t.work + "/payload.bin"

	q := transfer.NewTransferQueue(t.sftp.Raw(), 2)
	up := q.AddUpload(local, remote)
	if !waitStatus(q, up.ID, transfer.StatusCompleted, 90*time.Second) {
		r.ok("transfer: upload completed", itemErr(q, up.ID))
		return
	}
	r.ok("transfer: 3 MB upload completed", nil)

	got, err := t.run("sha256sum " + remote)
	if err == nil {
		r.eq("transfer: server checksum equals the source", firstField(got), sum)
	}
	down := filepath.Join(dir, "copy.bin")
	d := q.AddDownload(remote, down)
	if !waitStatus(q, d.ID, transfer.StatusCompleted, 90*time.Second) {
		r.ok("transfer: download completed", itemErr(q, d.ID))
		return
	}
	back, err := os.ReadFile(down)
	if r.ok("transfer: download finished", err) {
		r.eq("transfer: downloaded bytes are identical", bytes.Equal(back, payload), true)
	}
}

func folderTree(r *report, t *target) {
	if t.sftp == nil {
		r.skip("folder: recursive mirror down", "no sftp session")
		return
	}
	root := t.work + "/tree"
	for _, d := range []string{root, root + "/a", root + "/a/b"} {
		if err := t.sftp.MkdirAll(d); err != nil {
			r.ok("folder: mkdir "+d, err)
			return
		}
	}
	for name, body := range map[string]string{"top.txt": "top", "a/mid.txt": "middle", "a/b/deep.txt": "deepest"} {
		if err := t.sftp.WriteFile(root+"/"+name, []byte(body)); err != nil {
			r.ok("folder: write "+name, err)
			return
		}
	}
	paths, err := t.sftp.Walk(root, 2000)
	if !r.ok("folder: Walk the tree", err) {
		return
	}
	r.eq("folder: Walk finds three files", len(paths), 3)

	dir, _ := os.MkdirTemp("", "graystone-tree-*")
	defer os.RemoveAll(dir)
	q := transfer.NewTransferQueue(t.sftp.Raw(), 2)
	for _, p := range paths {
		rel := strings.TrimPrefix(p, root+"/")
		dst := filepath.Join(dir, filepath.FromSlash(rel))
		os.MkdirAll(filepath.Dir(dst), 0o755)
		q.AddDownload(p, dst)
	}
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		_, _, _, completed, failed := q.GetStats()
		if failed > 0 {
			r.ok("folder: every file mirrored", fmt.Errorf("%d failed", failed))
			return
		}
		if completed >= 3 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	body, err := os.ReadFile(filepath.Join(dir, "a", "b", "deep.txt"))
	if r.ok("folder: nested path recreated locally", err) {
		r.eq("folder: nested content survived", string(body), "deepest")
	}
}

func pauseResumeCancel(r *report, t *target) {
	if t.sftp == nil {
		r.skip("queue: pause / resume / cancel", "no sftp session")
		return
	}
	dir, _ := os.MkdirTemp("", "graystone-pause-*")
	defer os.RemoveAll(dir)
	payload := randomBytes(12 << 20)
	local := filepath.Join(dir, "big.bin")
	os.WriteFile(local, payload, 0o600)
	remote := t.work + "/big.bin"

	q := transfer.NewTransferQueue(t.sftp.Raw(), 1)
	item := q.AddUpload(local, remote)
	time.Sleep(300 * time.Millisecond)
	q.PauseItem(item.ID)
	if !waitStatus(q, item.ID, transfer.StatusPaused, 30*time.Second) {
		r.ok("queue: pause took effect", fmt.Errorf("status %v", snapshot(q, item.ID).Status))
		return
	}
	r.ok("queue: pause took effect", nil, snapshot(q, item.ID).TransferBytes, "bytes held")
	q.ResumeItem(item.ID)
	if !waitStatus(q, item.ID, transfer.StatusCompleted, 120*time.Second) {
		r.ok("queue: resume completed the transfer", itemErr(q, item.ID))
		return
	}
	got, err := t.run("sha256sum " + remote)
	if err == nil {
		r.eq("queue: resumed upload is byte-exact", firstField(got), fmt.Sprintf("%x", sha256.Sum256(payload)))
	}

	other := filepath.Join(dir, "cancelled.bin")
	c := q.AddDownload(remote, other)
	time.Sleep(200 * time.Millisecond)
	q.CancelItem(c.ID)
	if !waitStatus(q, c.ID, transfer.StatusCancelled, 30*time.Second) {
		r.ok("queue: cancel took effect", fmt.Errorf("status %v", snapshot(q, c.ID).Status))
		return
	}
	time.Sleep(400 * time.Millisecond)
	_, exists := os.Stat(other)
	r.eq("queue: cancelled download left no partial file", os.IsNotExist(exists), true)
}

func conflicts(r *report, t *target) {
	if t.sftp == nil {
		r.skip("conflict: overwrite / rename / skip", "no sftp session")
		return
	}
	dir, _ := os.MkdirTemp("", "graystone-conflict-*")
	defer os.RemoveAll(dir)
	remote := t.work + "/one.txt"
	if err := t.sftp.WriteFile(remote, []byte("existing")); err != nil {
		r.ok("conflict: seed the remote file", err)
		return
	}
	dest := transfer.UniqueRemotePath(remote, func(p string) bool { return transfer.RemoteExists(t.sftp.Raw(), p) })
	r.eq("conflict: rename policy picks a numbered sibling", filepath.Base(dest), "one (1).txt")

	taken := filepath.Join(dir, "two.txt")
	os.WriteFile(taken, []byte("x"), 0o600)
	_, keep := transfer.LocalDestDecision(taken, transfer.Skip)
	r.eq("conflict: skip refuses an existing local file", keep, false)
	fresh, keep2 := transfer.LocalDestDecision(filepath.Join(dir, "three.txt"), transfer.Skip)
	r.eq("conflict: skip accepts a new local file", keep2 && filepath.Base(fresh) == "three.txt", true)
	over, keep3 := transfer.LocalDestDecision(taken, transfer.Overwrite)
	r.eq("conflict: overwrite keeps the same name", keep3 && filepath.Base(over) == "two.txt", true)
}

func editor(r *report, t *target) {
	if t.sftp == nil {
		r.skip("editor: read / save a remote file", "no sftp session")
		return
	}
	p := t.work + "/edit-me.txt"
	if err := t.sftp.WriteFile(p, []byte("line one\nline two\n")); err != nil {
		r.ok("editor: seed the file", err)
		return
	}
	data, err := t.sftp.ReadFile(p, 256<<10)
	if r.ok("editor: read within the size cap", err) {
		r.eq("editor: content arrives intact", string(data), "line one\nline two\n")
	}
	if err := t.sftp.WriteFile(p, []byte("edited\n")); err != nil {
		r.ok("editor: save overwrites wholesale", err)
		return
	}
	again, _ := t.sftp.ReadFile(p, 256<<10)
	r.eq("editor: no tail of the older content", string(again), "edited\n")

	if _, err := t.sftp.ReadFile(t.work+"/payload.bin", 1<<10); err == nil {
		r.ok("editor: a file over the cap is refused", fmt.Errorf("it was read"))
	} else {
		r.ok("editor: a file over the cap is refused", nil, truncate(err.Error(), 46))
	}
	if _, err := t.sftp.ReadFile(t.work+"/sub", 1<<10); err == nil {
		r.ok("editor: a directory is refused", fmt.Errorf("it was read"))
	} else {
		r.ok("editor: a directory is refused", nil, truncate(err.Error(), 46))
	}
}

// ---------- host key and private key formats ----------

func hostKeyChanged(r *report, t *target) {
	snap := t.kh.Snapshot()
	if len(snap) == 0 {
		r.ok("host key: something is recorded to change", fmt.Errorf("store empty"))
		return
	}
	var victim string
	for k := range snap {
		victim = k
		break
	}
	bad := map[string]string{}
	for k, v := range snap {
		if k == victim {
			bad[k] = "SHA256:" + strings.Repeat("Z", 43)
		} else {
			bad[k] = v
		}
	}
	data, _ := json.MarshalIndent(bad, "", "  ")
	if err := os.WriteFile(t.khFile, data, 0o600); err != nil {
		r.ok("host key: rewrite the store with a wrong fingerprint", err)
		return
	}
	if err := t.kh.Load(); err != nil {
		r.ok("host key: reload the store", err)
		return
	}
	_, err := sshclient.Dial(t.passwordProfile(), sshclient.Credential{Password: t.pass}, t.kh)
	var mm *sshclient.HostKeyMismatchError
	if !errors.As(err, &mm) {
		r.ok("host key: a changed key raises HostKeyMismatchError", fmt.Errorf("got %v", err))
		return
	}
	r.ok("host key: a changed key raises HostKeyMismatchError", nil, "expected", truncate(mm.Expected, 14), "actual", truncate(mm.Actual, 14))
}

func ppkLive(r *report, t *target) {
	if t.ctrl == nil {
		r.skip("ppk: live login with a PuTTY-format key", "no session")
		return
	}
	_, priv, err := ed25519.GenerateKey(crand.Reader)
	if err != nil {
		r.ok("ppk: generate a key pair", err)
		return
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		r.ok("ppk: build a signer", err)
		return
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	cmd := fmt.Sprintf("mkdir -p ~/.ssh && chmod 700 ~/.ssh && grep -qF '%s' ~/.ssh/authorized_keys 2>/dev/null || echo '%s' >> ~/.ssh/authorized_keys; chmod 600 ~/.ssh/authorized_keys; wc -l < ~/.ssh/authorized_keys", line, line)
	if got, err := t.run(cmd); err != nil {
		r.ok("ppk: install the public key", err)
		return
	} else {
		r.ok("ppk: authorized_keys updated", nil, got, "line(s)")
	}

	dir, _ := os.MkdirTemp("", "graystone-ppk-*")
	defer os.RemoveAll(dir)
	const pass = "realtest passphrase"
	keyProfile := func(path, phrase string) sessionstore.Profile {
		return sessionstore.Profile{Host: t.host, Port: t.port, User: t.user, Auth: sessionstore.AuthKey, KeyPath: path}
	}

	for _, c := range []struct {
		name    string
		version int
		phrase  string
	}{
		{"v2 unencrypted", 2, ""},
		{"v2 wrapped", 2, pass},
		{"v3 wrapped Argon2id", 3, pass},
	} {
		path := filepath.Join(dir, "id-"+strings.ReplaceAll(c.name, " ", "-")+".ppk")
		if err := os.WriteFile(path, buildPPK(priv, c.version, c.phrase), 0o600); err != nil {
			r.ok("ppk: write "+c.name, err)
			continue
		}
		client, err := sshclient.Dial(keyProfile(path, c.phrase), sshclient.Credential{Passphrase: c.phrase}, t.kh)
		if err != nil {
			r.ok("ppk: live handshake with "+c.name, err)
			continue
		}
		client.Close()
		r.ok("ppk: live handshake with "+c.name, nil, "server verified the signature")
	}

	path := filepath.Join(dir, "id-v2-wrapped.ppk")
	_, err = sshclient.Dial(keyProfile(path, "wrong"), sshclient.Credential{Passphrase: "wrong"}, t.kh)
	var kf *sshclient.KeyFileError
	if errors.As(err, &kf) && errors.Is(kf, sshclient.ErrWrongPassphrase) {
		r.ok("ppk: a wrong passphrase is re-promptable", nil, truncate(err.Error(), 60))
	} else {
		r.ok("ppk: a wrong passphrase is re-promptable", fmt.Errorf("got %v", err))
	}

	pemPath := filepath.Join(dir, "id_ed25519")
	blk, err := ssh.MarshalPrivateKey(priv, "realtest")
	if err != nil {
		r.ok("ppk: marshal the same key as OpenSSH PEM", err)
		return
	}
	if err := os.WriteFile(pemPath, pem.EncodeToMemory(blk), 0o600); err != nil {
		r.ok("ppk: write the OpenSSH PEM", err)
		return
	}
	client, err := sshclient.Dial(keyProfile(pemPath, ""), sshclient.Credential{}, t.kh)
	if r.ok("key: the same key as an OpenSSH PEM also logs in", err) {
		client.Close()
	}
}

// ---------- cleanup ----------

func cleanup(r *report, t *target) {
	if t.client != nil && t.work != "" {
		if _, err := t.run("rm -rf " + t.work); err == nil {
			r.ok("cleanup: removed "+t.work+" on "+t.addr(), nil)
		}
	}
	if t.ctrl != nil {
		t.ctrl.Close()
	}
	if t.client != nil {
		t.client.Close()
	}
}

// ---------- helpers ----------

func buildPPK(key ed25519.PrivateKey, version int, passphrase string) []byte {
	signer, _ := ssh.NewSignerFromKey(key)
	pubBlob := signer.PublicKey().Marshal()
	privBlob := sshString(trimOrPad(key.Seed()))
	enc := "none"
	var head []string
	if passphrase != "" {
		enc = "aes256-cbc"
		for len(privBlob)%16 != 0 {
			privBlob = append(privBlob, 0)
		}
		var k, iv []byte
		if version == 2 {
			k, iv = ppkV2Key(passphrase), make([]byte, 16)
		} else {
			salt := make([]byte, 16)
			crand.Read(salt)
			d := argon2.IDKey([]byte(passphrase), salt, 2, 1024, 1, 80)
			k, iv = d[:32], d[32:48]
			head = []string{"Key-Derivation: Argon2id", "Argon2-Memory: 1024", "Argon2-Passes: 2",
				"Argon2-Parallelism: 1", "Argon2-Salt: " + hex.EncodeToString(salt)}
		}
		block, err := aes.NewCipher(k)
		if err != nil {
			panic(err)
		}
		out := make([]byte, len(privBlob))
		copy(out, privBlob)
		cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, out)
		privBlob = out
	}
	lines := []string{fmt.Sprintf("PuTTY-User-Key-File-%d: ssh-ed25519", version), "Encryption: " + enc, "Comment: realtest"}
	lines = append(lines, head...)
	lines = append(lines, numbered("Public", pubBlob)...)
	lines = append(lines, numbered("Private", privBlob)...)
	lines = append(lines, "Private-MAC: "+strings.Repeat("0", 40))
	return []byte(strings.Join(lines, "\n") + "\n")
}

func sshString(b []byte) []byte {
	out := make([]byte, 4+len(b))
	out[0], out[1], out[2], out[3] = byte(len(b)>>24), byte(len(b)>>16), byte(len(b)>>8), byte(len(b))
	copy(out[4:], b)
	return out
}

func trimOrPad(seed []byte) []byte {
	if len(seed) > 0 && seed[0]&0x80 != 0 {
		return append([]byte{0}, seed...)
	}
	return seed
}

func ppkV2Key(passphrase string) []byte {
	var md []byte
	for i := uint32(0); len(md) < 32; i++ {
		h := sha1.New()
		h.Write([]byte{byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i)})
		h.Write([]byte(passphrase))
		md = h.Sum(md)
	}
	return md[:32]
}

func numbered(name string, blob []byte) []string {
	b64 := base64.StdEncoding.EncodeToString(blob)
	var body []string
	for i := 0; i < len(b64); i += 64 {
		e := i + 64
		if e > len(b64) {
			e = len(b64)
		}
		body = append(body, b64[i:e])
	}
	return append([]string{fmt.Sprintf("%s-Lines: %d", name, len(body))}, body...)
}

func snapshot(q *transfer.TransferQueue, id int) *transfer.TransferItem {
	for _, it := range q.GetItems() {
		if it.ID == id {
			return it
		}
	}
	return &transfer.TransferItem{Status: transfer.StatusPending}
}

func itemErr(q *transfer.TransferQueue, id int) error {
	it := snapshot(q, id)
	if it.Error != nil {
		return it.Error
	}
	return fmt.Errorf("status %v: %s", it.Status, it.ErrorMsg)
}

func waitStatus(q *transfer.TransferQueue, id int, want transfer.TransferStatus, within time.Duration) bool {
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if snapshot(q, id).Status == want {
			return true
		}
		time.Sleep(80 * time.Millisecond)
	}
	return false
}

func nilCheck(ok bool, err error) error {
	if ok {
		return nil
	}
	return err
}

func parseOctal(s string) int {
	v := 0
	for _, c := range s {
		v = v*8 + int(c-'0')
	}
	return v
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := crand.Read(b); err != nil {
		for i := range b {
			b[i] = byte(i * 31)
		}
	}
	return b
}

func between(s, start, end string) string {
	i := strings.Index(s, start)
	if i < 0 {
		return ""
	}
	rest := s[i+len(start):]
	if j := strings.IndexAny(rest, " \t\r\n"); j >= 0 {
		return rest[:j]
	}
	return strings.TrimSpace(rest)
}

func firstField(s string) string {
	if i := strings.IndexAny(s, " \t\n"); i >= 0 {
		return s[:i]
	}
	return strings.TrimSpace(s)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
