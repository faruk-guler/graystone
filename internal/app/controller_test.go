package app

import (
	"bytes"
	"crypto/ed25519"
	crand "crypto/rand"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"graystone/internal/sessionstore"
	"graystone/internal/sftpclient"
	"graystone/internal/sshclient"
)

// startEchoServer runs a minimal SSH server that authenticates by password and
// echoes the PTY byte stream, returning its listen address.
func startEchoServer(t *testing.T) string {
	t.Helper()
	return startServer(t, "")
}

// startServer runs a minimal SSH server. When exitOn is non-empty the fake
// shell closes the PTY channel as soon as it sees that text, which is how a
// remote "exit"/logout tears the session down.
func startServer(t *testing.T, exitOn string) string {
	t.Helper()
	_, hostPriv, err := ed25519.GenerateKey(crand.Reader)
	if err != nil {
		t.Fatalf("host key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if string(pass) == "pw" {
				return nil, nil
			}
			return nil, fmt.Errorf("denied")
		},
	}
	cfg.AddHostKey(signer)

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
			go handle(nc, cfg, exitOn)
		}
	}()
	return ln.Addr().String()
}

func handle(nc net.Conn, cfg *ssh.ServerConfig, exitOn string) {
	sc, chans, reqs, err := ssh.NewServerConn(nc, cfg)
	if err != nil {
		return
	}
	defer sc.Close()
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
				case "pty-req", "env":
					if req.WantReply {
						req.Reply(true, nil)
					}
				case "shell":
					if req.WantReply {
						req.Reply(true, nil)
					}
					// The echo only starts for a PTY channel: a subsystem channel
					// carries SFTP frames, and writing a prompt into it would corrupt
					// the protocol.
					go echoChannel(ch, exitOn)
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
					if req.WantReply {
						req.Reply(false, nil)
					}
				default:
					if req.WantReply {
						req.Reply(false, nil)
					}
				}
			}
		}(requests)
	}
}

// echoChannel writes the login prompt and then reflects the stream back, which
// is enough for the terminal model tests. With exitOn set it closes the channel
// as soon as that text arrives, like a remote logout.
func echoChannel(ch ssh.Channel, exitOn string) {
	fmt.Fprint(ch, "welcome$ ")
	if exitOn == "" {
		io.Copy(ch, ch)
		ch.Close()
		return
	}
	buf := make([]byte, 256)
	var seen strings.Builder
	for {
		n, err := ch.Read(buf)
		if n > 0 {
			ch.Write(buf[:n])
			seen.Write(buf[:n])
			if strings.Contains(seen.String(), exitOn) {
				fmt.Fprint(ch, "\r\nlogout\r\n")
				ch.Close()
				return
			}
		}
		if err != nil {
			ch.Close()
			return
		}
	}
}

func newController(t *testing.T, addr string, onOutput func()) *Controller {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	var port int
	fmt.Sscanf(portStr, "%d", &port)
	prof := sessionstore.Profile{Host: host, Port: port, User: "root", Auth: sessionstore.AuthPassword}
	kh := sshclient.NewKnownHosts(t.TempDir())
	if err := kh.Load(); err != nil {
		t.Fatalf("kh load: %v", err)
	}
	return New(prof, sshclient.Credential{Password: "pw"}, kh, onOutput)
}

func TestControllerConnectAndEcho(t *testing.T) {
	addr := startEchoServer(t)

	var updates atomic.Int64
	c := newController(t, addr, func() { updates.Add(1) })
	sink := newRawSink(c) // subscribe before Connect so "welcome$" is captured
	defer c.Close()

	if err := c.Connect(80, 24); err != nil {
		t.Fatalf("connect: %v", err)
	}
	if c.State() != StateConnected {
		t.Fatalf("state = %v, want connected", c.State())
	}

	// The prompt should arrive via the raw stream.
	if err := waitForText(sink, "welcome$", 3*time.Second); err != nil {
		t.Fatalf("wait prompt: %v", err)
	}

	// Send a command; the fake PTY echoes it back, so it must appear in output.
	if err := c.WriteInput([]byte("ping\r")); err != nil {
		t.Fatalf("write input: %v", err)
	}
	if err := waitForText(sink, "ping", 3*time.Second); err != nil {
		t.Fatalf("wait echo: %v", err)
	}
	if updates.Load() == 0 {
		t.Fatal("expected at least one onOutput notification")
	}

	// Resize must not panic or return an error (void API); it sends the new
	// dimensions to the remote PTY via the shell. With no local model, the only
	// check is that the call completes cleanly.
	c.Resize(100, 30)
}

func TestControllerConnectFailure(t *testing.T) {
	addr := startEchoServer(t)
	c := newController(t, addr, nil)
	// Override the credential to force an auth failure.
	c.cred = sshclient.Credential{Password: "wrong"}
	err := c.Connect(80, 24)
	if err == nil {
		t.Fatal("expected connect error")
	}
	if c.State() != StateFailed {
		t.Fatalf("state = %v, want failed", c.State())
	}
	if c.Err() == nil {
		t.Fatal("expected recorded error")
	}
}

// TestControllerFiresExitOnLogout proves the shell ending on its own is
// announced: without it the UI keeps showing a tab whose transport is dead.
func TestControllerFiresExitOnLogout(t *testing.T) {
	addr := startServer(t, "exit")
	c := newController(t, addr, nil)
	sink := newRawSink(c)
	defer c.Close()

	exited := make(chan struct{}, 1)
	c.OnExit(func() {
		select {
		case exited <- struct{}{}:
		default:
		}
	})

	if err := c.Connect(80, 24); err != nil {
		t.Fatalf("connect: %v", err)
	}
	if err := waitForText(sink, "welcome$", 3*time.Second); err != nil {
		t.Fatalf("wait prompt: %v", err)
	}
	if err := c.WriteInput([]byte("exit\r")); err != nil {
		t.Fatalf("write exit: %v", err)
	}

	select {
	case <-exited:
	case <-time.After(3 * time.Second):
		t.Fatal("OnExit was not called after the remote shell logged out")
	}
	if st := c.State(); st != StateDisconnected {
		t.Fatalf("state = %v, want disconnected", st)
	}
}

// TestControllerNoExitOnClose guards the other half: a shutdown the app asked
// for must not be reported as a surprise logout.
func TestControllerNoExitOnClose(t *testing.T) {
	addr := startEchoServer(t)
	c := newController(t, addr, nil)
	sink := newRawSink(c)

	exited := make(chan struct{}, 1)
	c.OnExit(func() {
		select {
		case exited <- struct{}{}:
		default:
		}
	})

	if err := c.Connect(80, 24); err != nil {
		t.Fatalf("connect: %v", err)
	}
	if err := waitForText(sink, "welcome$", 3*time.Second); err != nil {
		t.Fatalf("wait prompt: %v", err)
	}
	c.Close()

	select {
	case <-exited:
		t.Fatal("OnExit must not fire for a shutdown requested through Close")
	case <-time.After(300 * time.Millisecond):
	}
}

// TestSFTPDoubleOpenYieldsOneSession guards the lazy SFTP handshake, which runs
// with the controller lock released so a slow server cannot block Resize or
// WriteInput. That gap is exactly where two callers can overlap: file browsing
// and a folder download both ask for the session. They must end up on the single
// installed client - a second live SFTP channel means a second set of handles,
// and only one of them is ever closed.
func TestSFTPDoubleOpenYieldsOneSession(t *testing.T) {
	addr := startEchoServer(t)
	c := newController(t, addr, nil)
	defer c.Close()

	if err := c.Connect(80, 24); err != nil {
		t.Fatalf("connect: %v", err)
	}

	const racers = 8
	start := make(chan struct{})
	type outcome struct {
		cli *sftpclient.Client
		err error
	}
	results := make(chan outcome, racers)
	for i := 0; i < racers; i++ {
		go func() {
			<-start
			cli, err := c.SFTP()
			results <- outcome{cli, err}
		}()
	}
	close(start)

	var first *sftpclient.Client
	for i := 0; i < racers; i++ {
		r := <-results
		if r.err != nil {
			t.Fatalf("SFTP(): %v", r.err)
		}
		if r.cli == nil {
			t.Fatal("SFTP() returned no client")
		}
		if first == nil {
			first = r.cli
			continue
		}
		if r.cli != first {
			t.Fatal("two callers were handed different SFTP sessions")
		}
	}

	// Once installed, later calls reuse it instead of negotiating again.
	again, err := c.SFTP()
	if err != nil || again != first {
		t.Fatalf("second SFTP() = %p/%v, want the installed session %p", again, err, first)
	}
}

// rawSink accumulates every PTY byte broadcast through c.SubscribeRaw so tests
// can search for text that appeared before they started checking. It replaces
// the old vt10x-based PlainText approach with a simple byte collector.
type rawSink struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

// newRawSink installs a permanent subscriber on c and returns the sink.
// Call it BEFORE c.Connect so the first output prompt is captured.
func newRawSink(c *Controller) *rawSink {
	s := &rawSink{}
	c.SubscribeRaw(func(b []byte) {
		s.mu.Lock()
		s.buf.Write(b)
		s.mu.Unlock()
	})
	return s
}

func waitForText(s *rawSink, substr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		text := s.buf.String()
		s.mu.Unlock()
		if strings.Contains(text, substr) {
			return nil
		}
		time.Sleep(20 * time.Millisecond)
	}
	s.mu.Lock()
	text := s.buf.String()
	s.mu.Unlock()
	return fmt.Errorf("timed out waiting for %q; got=%q", substr, text)
}

// startStallServer completes the handshake and authenticates like the echo
// server, then parks its handler without reading or answering anything else -
// the silent-half-open link that the pump can never notice because no read
// ever returns a failure. When drop is true the parked transport is torn down
// (abruptly, RST-style) right after the handshake instead, which the pump sees
// immediately as a read error.
func startStallServer(t *testing.T, drop bool) string {
	t.Helper()
	_, hostPriv, err := ed25519.GenerateKey(crand.Reader)
	if err != nil {
		t.Fatalf("host key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if string(pass) == "pw" {
				return nil, nil
			}
			return nil, fmt.Errorf("denied")
		},
	}
	cfg.AddHostKey(signer)

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
			go func() {
				sc, chans, reqs, err := ssh.NewServerConn(nConn, cfg)
				if err != nil {
					return
				}
				_ = reqs // deliberately never read: probes must go unanswered
				// The stall half: never read reqs (service-accept is answered
				// inside x/crypto during the handshake), so every keepalive probe
				// afterwards sits unanswered in the queue. Accept the session and
				// reply to its pty/shell requests so Connect finishes - then send
				// no PTY data ever, the silent half-open link the pump cannot see.
				if drop {
					sc.Close()
					if tc, ok := nConn.(*net.TCPConn); ok {
						_ = tc.SetLinger(0) // RST, not a clean goodbye
					}
					_ = nConn.Close()
					return
				}
				go func() {
					for newChan := range chans {
						if newChan.ChannelType() != "session" {
							newChan.Reject(ssh.UnknownChannelType, "no")
							continue
						}
						_, requests, err := newChan.Accept()
						if err != nil {
							continue
						}
						go func(in <-chan *ssh.Request) {
							for req := range in {
								if req.WantReply {
									_ = req.Reply(true, nil)
								}
							}
						}(requests)
					}
				}()
				// Park: keep the TCP path open forever, answer nothing else.
				select {}
			}()
		}
	}()
	return ln.Addr().String()
}

// TestKeepaliveKeepsHealthySession is the false-positive guard: the probe runs
// against a server that refuses unknown global requests (the common real-world
// reply) and must never consider that a failure, or every idle session would be
// dropped after three intervals.
func TestKeepaliveKeepsHealthySession(t *testing.T) {
	origInterval, origWait := keepaliveInterval, keepaliveProbeWait
	keepaliveInterval, keepaliveProbeWait = 30*time.Millisecond, 200*time.Millisecond
	defer func() { keepaliveInterval, keepaliveProbeWait = origInterval, origWait }()

	addr := startEchoServer(t)
	c := newController(t, addr, nil)
	sink := newRawSink(c)
	defer c.Close()

	exited := make(chan struct{}, 1)
	c.OnExit(func() { exited <- struct{}{} })
	deaths := make(chan string, 4)
	c.OnDeath(func(text string) { deaths <- text })

	if err := c.Connect(80, 24); err != nil {
		t.Fatalf("connect: %v", err)
	}
	if err := waitForText(sink, "welcome$", 3*time.Second); err != nil {
		t.Fatalf("wait prompt: %v", err)
	}
	time.Sleep(500 * time.Millisecond) // many probe intervals

	select {
	case <-exited:
		t.Fatal("a healthy session was torn down by the keepalive")
	default:
	}
	select {
	case d := <-deaths:
		t.Fatalf("keepalive reported a death on a healthy link: %q", d)
	default:
	}
	if c.State() != StateConnected {
		t.Fatalf("state = %v, want connected", c.State())
	}
}

// TestKeepaliveDropsZombieConnection is the point of the whole feature: a link
// whose far side stopped answering anything (NAT dropped the mapping, server
// froze) produces no read error, so without the probe the terminal would hang
// on screen forever. After the consecutive-failure threshold the client must
// declare it dead, announce why, and let the exit path drop the tab.
func TestKeepaliveDropsZombieConnection(t *testing.T) {
	origInterval, origWait, origFails := keepaliveInterval, keepaliveProbeWait, keepaliveMaxFailures
	keepaliveInterval, keepaliveProbeWait, keepaliveMaxFailures = 30*time.Millisecond, 60*time.Millisecond, 3
	defer func() {
		keepaliveInterval, keepaliveProbeWait, keepaliveMaxFailures = origInterval, origWait, origFails
	}()

	addr := startStallServer(t, false)
	c := newController(t, addr, nil)
	defer c.Close()

	deaths := make(chan string, 4)
	c.OnDeath(func(text string) { deaths <- text })
	exited := make(chan struct{}, 1)
	c.OnExit(func() { exited <- struct{}{} })

	if err := c.Connect(80, 24); err != nil {
		t.Fatalf("connect: %v", err)
	}

	select {
	case d := <-deaths:
		if !strings.Contains(d, "keepalive") {
			t.Fatalf("death notice should name the keepalive, got %q", d)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("zombie connection was never declared dead")
	}
	select {
	case <-exited:
	case <-time.After(3 * time.Second):
		t.Fatal("closing the dead client must run the exit path so the tab drops")
	}
	if st := c.State(); st == StateConnected {
		t.Fatal("state must not stay connected after the keepalive gave up")
	}
}

// TestKeepaliveStopsOnClose keeps the goroutine honest: a controller closed
// with a live transport must stop probing instead of ticking against a client
// nobody owns any more.
func TestKeepaliveStopsOnClose(t *testing.T) {
	addr := startEchoServer(t)
	c := newController(t, addr, nil)
	if err := c.Connect(80, 24); err != nil {
		t.Fatalf("connect: %v", err)
	}
	c.Close()
	// No panic, no probe against the closed client: the loop exits on closeCh.
	deaths := make(chan string, 1)
	c.OnDeath(func(text string) { deaths <- text })
	time.Sleep(200 * time.Millisecond)
	select {
	case d := <-deaths:
		t.Fatalf("closed controller kept reporting deaths: %q", d)
	default:
	}
}
