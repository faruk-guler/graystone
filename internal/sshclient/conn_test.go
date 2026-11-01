package sshclient

import (
	"bytes"
	"crypto/ed25519"
	crand "crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"graystone/internal/sessionstore"
)

const testPassword = "s3cr3t-pw"

// testOptions configures what the in-process server accepts, so one listener
// can play a 2FA box, a cold keyboard-interactive rejecter or a plain password
// host without rewriting the handshake each time.
type testOptions struct {
	// Password, when non-empty, is accepted by the password method.
	Password string
	// KeyboardInteractive, when non-nil, answers the kbdint method with these
	// prompts instead of rejecting it outright.
	KeyboardInteractive func(challenge ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error)
	// AuthorizedKey, when non-nil, is the only public key the publickey method
	// accepts. It lets a test prove a parsed key really signs a live handshake
	// rather than merely round-tripping through the same code that wrote it.
	AuthorizedKey ssh.PublicKey
}

// startTestServer runs an in-process SSH server that authenticates by password
// and echoes anything sent to its PTY shell. It returns the listen address.
func startTestServer(t *testing.T) string {
	t.Helper()
	return startAuthServer(t, testOptions{Password: testPassword})
}

// startAuthServer is the shared listener: same host key generation and PTY
// echo as startTestServer, but the auth callbacks come from opts. It is the
// real-server half of the keyboard-interactive tests - the point of those is
// that a live server negotiates the method, so a hand-written challenge list
// could not prove the flow.
func startAuthServer(t *testing.T, opts testOptions) string {
	t.Helper()

	_, hostPriv, err := ed25519.GenerateKey(crand.Reader)
	if err != nil {
		t.Fatalf("host key: %v", err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatalf("host signer: %v", err)
	}

	cfg := &ssh.ServerConfig{}
	if opts.Password != "" {
		cfg.PasswordCallback = func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if c.User() == "root" && string(pass) == opts.Password {
				return nil, nil
			}
			return nil, fmt.Errorf("auth denied")
		}
	}
	if opts.KeyboardInteractive != nil {
		cb := opts.KeyboardInteractive
		cfg.KeyboardInteractiveCallback = func(c ssh.ConnMetadata, challenge ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			if c.User() != "root" {
				return nil, fmt.Errorf("auth denied")
			}
			return cb(challenge)
		}
	}
	if opts.AuthorizedKey != nil {
		want := opts.AuthorizedKey
		cfg.PublicKeyCallback = func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if c.User() == "root" && bytes.Equal(key.Marshal(), want.Marshal()) {
				return nil, nil
			}
			return nil, fmt.Errorf("auth denied")
		}
	}
	cfg.AddHostKey(hostSigner)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			nConn, err := ln.Accept()
			if err != nil {
				return // listener closed
			}
			go handleConn(nConn, cfg)
		}
	}()
	return ln.Addr().String()
}

func handleConn(nConn net.Conn, cfg *ssh.ServerConfig) {
	sshConn, chans, reqs, err := ssh.NewServerConn(nConn, cfg)
	if err != nil {
		return
	}
	defer sshConn.Close()
	go ssh.DiscardRequests(reqs)

	for newChan := range chans {
		if newChan.ChannelType() != "session" {
			newChan.Reject(ssh.UnknownChannelType, "only sessions supported")
			continue
		}
		ch, requests, err := newChan.Accept()
		if err != nil {
			continue
		}
		go func(in <-chan *ssh.Request) {
			for req := range in {
				switch req.Type {
				case "pty-req", "shell", "env":
					if req.WantReply {
						req.Reply(true, nil)
					}
				default:
					if req.WantReply {
						req.Reply(false, nil)
					}
				}
			}
		}(requests)
		go func() {
			// Prompt once, then echo the byte stream back.
			fmt.Fprint(ch, "graystone-test$ ")
			io.Copy(ch, ch)
			ch.Close()
		}()
	}
}

// TestAuthFailedClassifiesRealServerRejection pins the wording that the retry
// loop depends on: the error must come from an actual handshake against a
// server that denied the password, not from a hand-written string.
func TestAuthFailedClassifiesRealServerRejection(t *testing.T) {
	addr := startTestServer(t)
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	var port int
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		t.Fatalf("parse port: %v", err)
	}

	kh := NewKnownHosts(t.TempDir())
	if err := kh.Load(); err != nil {
		t.Fatalf("kh load: %v", err)
	}
	prof := sessionstore.Profile{Host: host, Port: port, User: "root", Auth: sessionstore.AuthPassword}

	if _, err := Dial(prof, Credential{Password: "not-the-password"}, kh); err == nil {
		t.Fatal("expected the wrong password to be rejected")
	} else if !AuthFailed(err) {
		t.Fatalf("AuthFailed = false for a rejected password; err=%v", err)
	}

	// The same server must not classify a good password as an auth failure.
	if client, err := Dial(prof, Credential{Password: testPassword}, kh); err != nil {
		t.Fatalf("dial with correct password: %v", err)
	} else {
		_ = client.Close()
	}
}

// TestAuthFailedIgnoresTransportErrors keeps a refused connection from being
// mistaken for a bad credential, which would prompt the user for nothing.
func TestAuthFailedIgnoresTransportErrors(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	var port int
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		t.Fatalf("parse port: %v", err)
	}
	ln.Close() // nothing is listening any more

	kh := NewKnownHosts(t.TempDir())
	if err := kh.Load(); err != nil {
		t.Fatalf("kh load: %v", err)
	}
	prof := sessionstore.Profile{Host: host, Port: port, User: "root", Auth: sessionstore.AuthPassword}

	if _, err := Dial(prof, Credential{Password: testPassword}, kh); err == nil {
		t.Fatal("expected a connection failure")
	} else if AuthFailed(err) {
		t.Fatalf("AuthFailed = true for a transport error; err=%v", err)
	}

	if AuthFailed(nil) {
		t.Fatal("AuthFailed(nil) must be false")
	}
	if !AuthFailed(fmt.Errorf("sshclient: dial x: ssh: unable to authenticate, attempted methods [none password]")) {
		t.Fatal("AuthFailed must match the library's rejection message")
	}
}

// dialTrusted performs the two-step the app itself does: a host nobody has met
// yet comes back as UnknownHostError, and only after the user's trust is
// recorded does the handshake succeed.
func dialTrusted(t *testing.T, prof sessionstore.Profile, cred Credential, kh *KnownHosts) (*ssh.Client, error) {
	t.Helper()
	client, err := Dial(prof, cred, kh)
	var unk *UnknownHostError
	if errors.As(err, &unk) {
		if err := kh.Trust(unk.Addr, unk.Fingerprint); err != nil {
			t.Fatalf("trust %s: %v", unk.Addr, err)
		}
		client, err = Dial(prof, cred, kh)
	}
	if err != nil {
		return nil, err
	}
	return client, nil
}

// profileForAddr builds the password profile the tests dial against addr.
func profileForAddr(t *testing.T, addr string) sessionstore.Profile {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	var port int
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		t.Fatalf("parse port: %v", err)
	}
	return sessionstore.Profile{Host: host, Port: port, User: "root", Auth: sessionstore.AuthPassword}
}

// TestDialKeyboardInteractive2FA proves the two halves of interactive auth
// against a live server: the single "Password:" challenge is answered from the
// credential without asking anyone, and the extra token question reaches the
// Interact callback - which is how Graystone now logs into servers that only
// offer keyboard-interactive (OTP/2FA) instead of rejecting them.
func TestDialKeyboardInteractive2FA(t *testing.T) {
	addr := startAuthServer(t, testOptions{
		KeyboardInteractive: func(challenge ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			answers, err := challenge("", "", []string{"Password:", "Token code:"}, []bool{false, true})
			if err != nil {
				return nil, err
			}
			if len(answers) != 2 || answers[0] != testPassword || answers[1] != "123456" {
				return nil, fmt.Errorf("bad answers %q", answers)
			}
			return nil, nil
		},
	})
	prof := profileForAddr(t, addr)
	kh := NewKnownHosts(t.TempDir())
	if err := kh.Load(); err != nil {
		t.Fatalf("kh load: %v", err)
	}

	var asked []string
	// The server presents both questions in one challenge, so neither is the
	// auto-answerable single-password shape: every question routes through the
	// callback in order, and the answers must reach the server unshuffled.
	cred := Credential{Password: testPassword, Interact: func(question string, echo bool) (string, error) {
		asked = append(asked, question)
		if question == "Password:" {
			return testPassword, nil
		}
		return "123456", nil
	}}
	client, err := Dial(prof, cred, kh)
	if err != nil {
		t.Fatalf("dial with 2FA: %v", err)
	}
	_ = client.Close()
	if len(asked) != 2 || asked[0] != "Password:" || asked[1] != "Token code:" {
		t.Fatalf("expected both questions routed through the callback in order, got %q", asked)
	}

	// A wrong token must fail the login, classified as an auth failure so the
	// UI re-prompts instead of tearing the session down for nothing.
	credBad := Credential{Password: testPassword, Interact: func(question string, echo bool) (string, error) {
		if question == "Password:" {
			return testPassword, nil
		}
		return "000000", nil
	}}
	if _, err := Dial(prof, credBad, NewKnownHosts(t.TempDir())); err == nil || !AuthFailed(err) {
		t.Fatalf("wrong token: err=%v, want an auth failure", err)
	}
}

// TestDialColdKeyboardInteractiveFallback pins the behaviour for servers that
// advertise keyboard-interactive but reject its initiation before any challenge
// (dropbear without PAM, root-with-keys-only). x/crypto aborts the whole
// handshake there with "unexpected message type 51 (expected 60)"; Graystone must
// re-dial without the method and still log in with the password.
func TestDialColdKeyboardInteractiveFallback(t *testing.T) {
	addr := startAuthServer(t, testOptions{
		Password: testPassword,
		KeyboardInteractive: func(challenge ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			return nil, fmt.Errorf("keyboard-interactive unavailable")
		},
	})
	prof := profileForAddr(t, addr)
	kh := NewKnownHosts(t.TempDir())
	if err := kh.Load(); err != nil {
		t.Fatalf("kh load: %v", err)
	}

	client, err := Dial(prof, Credential{Password: testPassword, Interact: func(string, bool) (string, error) {
		t.Fatal("a cold-rejected challenge must never reach the user")
		return "", nil
	}}, kh)
	if err != nil {
		t.Fatalf("dial through cold keyboard-interactive reject: %v", err)
	}
	_ = client.Close()
}

// TestDialWithoutInteractKeepsPlainAuth keeps the other side of the bridge:
// a credential with no callback never offers keyboard-interactive, so a plain
// password host still authenticates exactly as before and an interactive-only
// server fails honestly instead of parking on a challenge nobody answers.
func TestDialWithoutInteractKeepsPlainAuth(t *testing.T) {
	addr := startTestServer(t)
	prof := profileForAddr(t, addr)
	kh := NewKnownHosts(t.TempDir())
	if err := kh.Load(); err != nil {
		t.Fatalf("kh load: %v", err)
	}
	client, err := Dial(prof, Credential{Password: testPassword}, kh)
	if err != nil {
		t.Fatalf("plain password dial: %v", err)
	}
	_ = client.Close()

	kbdAddr := startAuthServer(t, testOptions{
		KeyboardInteractive: func(challenge ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			_, err := challenge("", "", []string{"Password: "}, []bool{false})
			if err != nil {
				return nil, err
			}
			return nil, nil
		},
	})
	kbdProf := profileForAddr(t, kbdAddr)
	_, err = Dial(kbdProf, Credential{Password: testPassword}, NewKnownHosts(t.TempDir()))
	if err == nil || !AuthFailed(err) {
		t.Fatalf("kbdint-only server without a callback: err=%v, want a clean auth failure", err)
	}
}

// TestDialKeyboardInteractiveAutoAnswersPassword covers the shape SuSE-style
// PAM boxes send: a single "Password: " challenge over keyboard-interactive.
// It must be answered straight from the credential without touching the UI -
// cred.Interact is set here only to prove it stays silent.
func TestDialKeyboardInteractiveAutoAnswersPassword(t *testing.T) {
	addr := startAuthServer(t, testOptions{
		KeyboardInteractive: func(challenge ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			answers, err := challenge("", "", []string{"Password: "}, []bool{false})
			if err != nil {
				return nil, err
			}
			if len(answers) != 1 || answers[0] != testPassword {
				return nil, fmt.Errorf("bad answers %q", answers)
			}
			return nil, nil
		},
	})
	prof := profileForAddr(t, addr)
	kh := NewKnownHosts(t.TempDir())
	if err := kh.Load(); err != nil {
		t.Fatalf("kh load: %v", err)
	}

	client, err := Dial(prof, Credential{Password: testPassword, Interact: func(question string, echo bool) (string, error) {
		t.Fatalf("single password challenge must not prompt the user (asked %q)", question)
		return "", nil
	}}, kh)
	if err != nil {
		t.Fatalf("dial password-over-kbdint: %v", err)
	}
	_ = client.Close()
}

// TestDialLegacyAlgorithmFallback is the old-server story: a peer that offers
// only pre-OpenSSH-7.4 transport (CBC cipher, SHA-1 HMAC, group14 kex, ssh-rsa
// host key) kills the modern-only first handshake mid-flight, and x/crypto
// surfaces that as io.EOF. Dial must quietly retry with the legacy set and
// connect - not report an opaque error for a server that is perfectly healthy
// for its era.
func TestDialLegacyAlgorithmFallback(t *testing.T) {
	rsaPriv, err := rsa.GenerateKey(crand.Reader, 1024)
	if err != nil {
		t.Fatalf("rsa host key: %v", err)
	}
	rsaSigner, err := ssh.NewSignerFromKey(rsaPriv)
	if err != nil {
		t.Fatalf("rsa signer: %v", err)
	}

	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if string(pass) == testPassword {
				return nil, nil
			}
			return nil, fmt.Errorf("denied")
		},
	}
	cfg.AddHostKey(rsaSigner)
	// A server restricted to the legacy set: the modern-only client offer has
	// no cipher in common, so the handshake is dropped exactly like an
	// OpenSSH_5.3 client would experience against Graystone today.
	cfg.Config = ssh.Config{
		KeyExchanges: []string{"diffie-hellman-group14-sha1"},
		Ciphers:      []string{"aes128-cbc"},
		MACs:         []string{"hmac-sha1"},
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			nConn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleConn(nConn, cfg)
		}
	}()

	prof := profileForAddr(t, ln.Addr().String())
	kh := NewKnownHosts(t.TempDir())
	if err := kh.Load(); err != nil {
		t.Fatalf("kh load: %v", err)
	}
	client, err := Dial(prof, Credential{Password: testPassword}, kh)
	if err != nil {
		t.Fatalf("dial legacy server: %v", err)
	}
	defer client.Close()

	// And the host key it trusts is the rsa-sha1 one, enrolled normally.
	kh2 := NewKnownHosts(filepath.Dir(kh.path))
	if err := kh2.Load(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if still := kh2.PendingError(prof.Addr()); still != nil {
		t.Fatal("legacy connection left a pending entry")
	}

	// Sanity: the legacy config really is unusable for the first attempt -
	// without the retry the dial fails the negotiation outright.
	if _, err := dialOnce(prof, Credential{Password: testPassword}, kh, nil, false); err == nil ||
		!isAlgorithmNegotiationFailure(err) {
		t.Fatalf("expected the modern-only offer to fail negotiation against the legacy server, got %v", err)
	}
}

// TestDialLegacyEOFSignature covers the other half of the trigger: a peer that
// hangs up mid-handshake (a truly ancient server, or one with a short socket
// timeout) reaches the retry through the bare io.EOF path, and a modern server
// that simply refuses keeps its ordinary error - the retry must not turn
// network failures into silent double dials.
func TestDialLegacyEOFSignature(t *testing.T) {
	// Eats the version banner, then drops the connection before any KEXINIT:
	// exactly the io.EOF an old server leaves on the wire.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			nConn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				b := make([]byte, 1)
				for {
					if _, err := c.Read(b[:1]); err != nil {
						break
					}
					if b[0] == '\n' {
						break
					}
				}
				_ = c.Close()
			}(nConn)
		}
	}()

	prof := profileForAddr(t, ln.Addr().String())
	kh := NewKnownHosts(t.TempDir())
	if err := kh.Load(); err != nil {
		t.Fatalf("kh load: %v", err)
	}
	if _, err := Dial(prof, Credential{Password: testPassword}, kh); err == nil ||
		!isAlgorithmNegotiationFailure(err) {
		t.Fatalf("banner-drop server: err=%v, want the EOF-flavoured failure after the retry", err)
	}

	// A refused port stays a transport error - no retry storm behind it.
	ln2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr2 := ln2.Addr().String()
	ln2.Close()
	prof2 := profileForAddr(t, addr2)
	if _, err := Dial(prof2, Credential{Password: testPassword}, NewKnownHosts(t.TempDir())); err == nil {
		t.Fatal("expected the refused port to fail")
	} else if isAlgorithmNegotiationFailure(err) {
		t.Fatalf("a refused connection must not read as an algorithm failure: %v", err)
	}
}

// TestDialReportsChangedHostKey is the classification the whole trust model
// depends on: when the recorded fingerprint no longer matches, Dial must hand
// back *HostKeyMismatchError. Collapsing it into UnknownHostError makes a changed
// key look like a first contact, and the UI then offers the same "Trust" click for
// a man-in-the-middle that it offers for a host the user has never met.
func TestDialReportsChangedHostKey(t *testing.T) {
	addr := startTestServer(t)
	prof := profileForAddr(t, addr)
	kh := NewKnownHosts(t.TempDir())

	client, err := Dial(prof, Credential{Password: testPassword}, kh)
	if err != nil {
		t.Fatalf("first dial: %v", err)
	}
	_ = client.Close()
	snap := kh.Snapshot()
	if len(snap) == 0 {
		t.Fatal("the first dial recorded nothing to compare against")
	}

	// Rewrite the store as if the host had rotated its key since it was trusted.
	bad := make(map[string]string, len(snap))
	for k, v := range snap {
		bad[k] = "SHA256:" + strings.Repeat("Q", 43)
		_ = v
	}
	data, err := json.Marshal(bad)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(kh.path, data, 0o600); err != nil {
		t.Fatalf("write store: %v", err)
	}
	if err := kh.Load(); err != nil {
		t.Fatalf("reload: %v", err)
	}

	_, err = Dial(prof, Credential{Password: testPassword}, kh)
	var mm *HostKeyMismatchError
	if !errors.As(err, &mm) {
		t.Fatalf("a changed host key must reach the caller as *HostKeyMismatchError, got %T: %v", err, err)
	}
	if mm.Expected == "" || mm.Actual == "" || mm.Addr != prof.Addr() {
		t.Errorf("the warning needs both fingerprints and the address: %+v", mm)
	}

	// And trusting the new key repairs it, which is the flow the mismatch dialog
	// exists to gate behind an explicit confirmation.
	if err := kh.Trust(mm.Addr, mm.Actual); err != nil {
		t.Fatalf("Trust the changed key: %v", err)
	}
	repaired, err := Dial(prof, Credential{Password: testPassword}, kh)
	if err != nil {
		t.Fatalf("dial after trusting the changed key: %v", err)
	}
	_ = repaired.Close()
}

func TestDialAndShellEcho(t *testing.T) {
	addr := startTestServer(t)
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	var port int
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		t.Fatalf("parse port: %v", err)
	}

	// A wrong password must fail authentication.
	badProf := sessionstore.Profile{Host: host, Port: port, User: "root", Auth: sessionstore.AuthPassword}
	khBad := NewKnownHosts(t.TempDir())
	khBad.Load()
	if _, err := Dial(badProf, Credential{Password: "wrong"}, khBad); err == nil {
		t.Fatal("expected auth failure with wrong password")
	}

	dir := t.TempDir()
	kh := NewKnownHosts(dir)
	if err := kh.Load(); err != nil {
		t.Fatalf("kh load: %v", err)
	}
	prof := sessionstore.Profile{Host: host, Port: port, User: "root", Auth: sessionstore.AuthPassword}

	client, err := Dial(prof, Credential{Password: testPassword}, kh)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	shell, err := StartShell(client, "xterm", 80, 24)
	if err != nil {
		t.Fatalf("start shell: %v", err)
	}
	defer shell.Close()

	if err := shell.Resize(100, 30); err != nil {
		t.Fatalf("resize: %v", err)
	}

	payload := "hello-graystone\r"
	if _, err := shell.WriteInput([]byte(payload)); err != nil {
		t.Fatalf("write input: %v", err)
	}

	// Read echoed output with a deadline so a hang fails the test clearly.
	type result struct {
		s   string
		err error
	}
	done := make(chan result, 1)
	go func() {
		buf := make([]byte, 256)
		var acc strings.Builder
		for {
			n, err := shell.Output().Read(buf)
			acc.Write(buf[:n])
			if strings.Contains(acc.String(), "hello-graystone") {
				done <- result{acc.String(), nil}
				return
			}
			if err != nil {
				done <- result{acc.String(), err}
				return
			}
		}
	}()

	select {
	case r := <-done:
		if r.err != nil && r.err != io.EOF {
			t.Fatalf("read output: %v", r.err)
		}
		if !strings.Contains(r.s, "hello-graystone") {
			t.Fatalf("expected echoed output to contain payload, got %q", r.s)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for echoed PTY output")
	}

	// The TOFU store should have enrolled the test host.
	khReload := NewKnownHosts(dir)
	if err := khReload.Load(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if len(khReload.hosts) != 1 {
		t.Fatalf("expected 1 enrolled host, got %d", len(khReload.hosts))
	}
}
