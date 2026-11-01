package app

import (
	"fmt"
	"io"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"gravel/internal/sessionstore"
	"gravel/internal/sftpclient"
	"gravel/internal/sshclient"
)

// State describes the lifecycle of a connection controller.
type State int

const (
	StateDisconnected State = iota
	StateConnecting
	StateConnected
	StateFailed
)

// String renders the state for UI display.
func (s State) String() string {
	switch s {
	case StateConnecting:
		return "connecting"
	case StateConnected:
		return "connected"
	case StateFailed:
		return "failed"
	default:
		return "disconnected"
	}
}

// Keepalive probe tuning. Var-style so the tests do not have to wait out the
// real budgets. Values follow what established Wails SSH terminals converged
// on: an interval short enough to beat NAT/firewall idle timeouts, a per-probe
// timeout, and a consecutive-failure count before a link is declared dead -
// one silent round trip is usually a busy server, not a dead one.
var (
	keepaliveInterval    = 30 * time.Second
	keepaliveProbeWait   = 10 * time.Second
	keepaliveMaxFailures = 3
)

// onDeath, when set, reports why the keepalive tore the connection down. The
// app layer injects a logger; tests leave it nil.
type deathNotice func(text string)

// Controller owns one server connection: the SSH client, an interactive PTY
// shell, and a lazily-opened SFTP session. It has no dependency on the GUI
// toolkit, so it is directly testable.
type Controller struct {
	prof sessionstore.Profile
	cred sshclient.Credential
	kh   *sshclient.KnownHosts

	mu     sync.Mutex
	state  State
	err    error
	client *ssh.Client
	shell  *sshclient.Shell
	sftpc  *sftpclient.Client

	onOutput func()
	onExit   func()
	onDeath  deathNotice
	closeCh  chan struct{}
	closed   sync.Once

	rawMu   sync.Mutex
	rawSubs map[int]func([]byte)
	rawSeq  int
}

// New builds a controller. onOutput (may be nil) is invoked from a background
// goroutine each time new PTY bytes arrive, so a UI layer can schedule a refresh.
func New(prof sessionstore.Profile, cred sshclient.Credential, kh *sshclient.KnownHosts, onOutput func()) *Controller {
	if onOutput == nil {
		onOutput = func() {}
	}
	return &Controller{
		prof:     prof,
		cred:     cred,
		kh:       kh,
		onOutput: onOutput,
		state:    StateDisconnected,
		closeCh:  make(chan struct{}),
	}
}

// OnDeath registers a callback the keepalive calls when it tears a dead link
// down, so the reason can reach the application log. Like OnExit it must not
// block.
func (c *Controller) OnDeath(fn func(text string)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onDeath = fn
}

// OnExit registers a callback invoked once when the remote shell stops on its
// own - a logout or a dropped connection. It never fires for a shutdown that
// was requested through Close. The callback runs on the pump goroutine, so it
// must not block.
func (c *Controller) OnExit(fn func()) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onExit = fn
}

// Connect dials the server and starts an interactive shell of the given size.
func (c *Controller) Connect(cols, rows int) error {
	if cols <= 0 {
		cols = 80
	}
	if rows <= 0 {
		rows = 24
	}
	c.mu.Lock()
	c.state = StateConnecting
	c.err = nil
	c.mu.Unlock()

	client, err := sshclient.Dial(c.prof, c.cred, c.kh)
	if err != nil {
		c.setFailed(err)
		return err
	}
	shell, err := sshclient.StartShell(client, "xterm-256color", cols, rows)
	if err != nil {
		client.Close()
		c.setFailed(err)
		return err
	}

	c.mu.Lock()
	if c.isClosedLocked() {
		c.mu.Unlock()
		shell.Close()
		client.Close()
		return fmt.Errorf("app: controller already closed")
	}
	c.client = client
	c.shell = shell
	c.state = StateConnected
	c.mu.Unlock()

	go c.pump(shell)
	go c.keepalive(client)
	return nil
}

// keepalive probes the transport with the OpenSSH standard global request.
// Custom request names are silently dropped by many servers, which turns a
// healthy link into a false positive when the probe waits for a reply.
// A reply (accepted or refused) proves the path is alive; only consecutive
// timeouts/transport errors count toward declaring the connection dead,
// because a single slow round trip under load is not an outage. Closing the
// client here is the teardown: the pump's next read fails, and the existing
// exit path drops the tab instead of leaving a frozen terminal behind.
func (c *Controller) keepalive(client *ssh.Client) {
	ticker := time.NewTicker(keepaliveInterval)
	defer ticker.Stop()
	fails := 0
	for {
		select {
		case <-c.closeCh:
			return
		case <-ticker.C:
			if !c.probe(client) {
				fails++
			}
			if fails == 0 || fails < keepaliveMaxFailures {
				continue
			}
			c.mu.Lock()
			live := c.client == client
			notice := c.onDeath
			c.mu.Unlock()
			if !live {
				return // a Close or a newer connection already owns the slot
			}
			if notice != nil {
				notice(fmt.Sprintf("keepalive: %d consecutive failed probes, dropping %s", fails, c.prof.Addr()))
			}
			_ = client.Close()
			return
		}
	}
}

// probe runs one want-reply global request with its own deadline. The request
// is fired in a goroutine because SendRequest parks until the transport either
// answers or dies; if the probe wins the race we reset the failure streak.
func (c *Controller) probe(client *ssh.Client) bool {
	reply := make(chan error, 1)
	go func() {
		_, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
		reply <- err
	}()
	timer := time.NewTimer(keepaliveProbeWait)
	defer timer.Stop()
	select {
	case <-reply:
		// err != nil after a refusal is protocol bookkeeping, not an outage:
		// any answer at all proves bytes still travel both ways.
		return true
	case <-timer.C:
		return false
	}
}

// pump reads PTY output until EOF/error and broadcasts each chunk to raw
// subscribers (xterm.js on the frontend). It does not maintain an internal
// terminal model: the per-session xterm.js instance in the frontend is the
// single source of truth for rendering, scrollback, and screen state.
func (c *Controller) pump(shell *sshclient.Shell) {
	// 32 KB matches the SSH channel's own packet size, so a wall of output costs
	// one read - and one UI event downstream - per packet instead of eight. A
	// short read still returns short, so interactive typing is unaffected.
	buf := make([]byte, 32*1024)
	for {
		n, err := shell.Output().Read(buf)
		if n > 0 {
			c.broadcastRaw(buf[:n])
			c.onOutput()
		}
		if err != nil {
			select {
			case <-c.closeCh:
				// normal shutdown requested by Close
			default:
				if err != io.EOF {
					c.setFailed(err)
				} else {
					c.markClosed()
				}
				// The shell is gone but the transport would otherwise stay open and
				// the UI would keep showing a dead tab, so announce it.
				c.fireExit()
			}
			return
		}
	}
}

// WriteInput forwards keyboard bytes to the remote PTY.
func (c *Controller) WriteInput(p []byte) error {
	c.mu.Lock()
	shell := c.shell
	c.mu.Unlock()
	if shell == nil {
		return fmt.Errorf("app: not connected")
	}
	_, err := shell.WriteInput(p)
	return err
}

// Resize updates the remote PTY window.
func (c *Controller) Resize(cols, rows int) {
	c.mu.Lock()
	shell := c.shell
	c.mu.Unlock()
	if shell != nil {
		_ = shell.Resize(cols, rows)
	}
}

// SFTP returns the session's SFTP client, opening it on first use. The SFTP
// subsystem negotiation is a network round trip, so it happens with c.mu
// released to avoid blocking unrelated callers (Resize, WriteInput, State)
// behind a slow or high-latency server.
func (c *Controller) SFTP() (*sftpclient.Client, error) {
	c.mu.Lock()
	if c.state != StateConnected || c.client == nil {
		c.mu.Unlock()
		return nil, fmt.Errorf("app: not connected")
	}
	if c.sftpc != nil {
		sc := c.sftpc
		c.mu.Unlock()
		return sc, nil
	}
	// Release the lock before the network handshake.
	sshClient := c.client
	c.mu.Unlock()

	sc, err := sftpclient.New(sshClient)
	if err != nil {
		return nil, err
	}

	// Re-acquire to install the result. Another goroutine may have finished
	// its own handshake first; use that one and discard ours so there is
	// exactly one SFTP session per controller.
	c.mu.Lock()
	if c.sftpc != nil {
		existing := c.sftpc
		c.mu.Unlock()
		_ = sc.Close()
		return existing, nil
	}
	c.sftpc = sc
	c.mu.Unlock()
	return sc, nil
}

// SSHClient exposes the underlying SSH connection so callers can open
// port-forwarding tunnels over the same session. It returns nil when not
// connected. Callers must not close it; the Controller owns its lifecycle.
func (c *Controller) SSHClient() *ssh.Client {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.client
}

// State returns the current connection state.
func (c *Controller) State() State {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state
}

// Err returns the last connection error, if any.
func (c *Controller) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

// Profile returns the profile this controller connects to.
func (c *Controller) Profile() sessionstore.Profile { return c.prof }

// Close tears down the session (SFTP, shell, SSH client).
func (c *Controller) Close() error {
	var err error
	c.closed.Do(func() {
		close(c.closeCh)
		c.mu.Lock()
		if c.sftpc != nil {
			err = c.sftpc.Close()
			c.sftpc = nil
		}
		if c.shell != nil {
			_ = c.shell.Close()
			c.shell = nil
		}
		if c.client != nil {
			_ = c.client.Close()
			c.client = nil
		}
		c.state = StateDisconnected
		c.mu.Unlock()
	})
	return err
}

func (c *Controller) fireExit() {
	c.mu.Lock()
	fn := c.onExit
	c.mu.Unlock()
	if fn != nil {
		fn()
	}
}

func (c *Controller) setFailed(err error) {
	c.mu.Lock()
	c.err = err
	if !c.isClosedLocked() {
		c.state = StateFailed
	}
	c.mu.Unlock()
}

func (c *Controller) markClosed() {
	c.mu.Lock()
	if !c.isClosedLocked() {
		c.state = StateDisconnected
	}
	c.mu.Unlock()
}

func (c *Controller) isClosedLocked() bool {
	select {
	case <-c.closeCh:
		return true
	default:
		return false
	}
}

// SubscribeRaw registers a callback that receives every raw PTY output chunk
// (the byte stream as it arrives, before vt10x rendering) so consumers like a
// WebSocket bridge can forward it to a browser terminal such as xterm.js.
// The returned cancel function unsubscribes. Callbacks run synchronously from
// the pump goroutine, one chunk at a time; they must not block for long.
func (c *Controller) SubscribeRaw(fn func([]byte)) (cancel func()) {
	c.rawMu.Lock()
	if c.rawSubs == nil {
		c.rawSubs = make(map[int]func([]byte))
	}
	id := c.rawSeq
	c.rawSeq++
	c.rawSubs[id] = fn
	c.rawMu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			c.rawMu.Lock()
			delete(c.rawSubs, id)
			c.rawMu.Unlock()
		})
	}
}

func (c *Controller) broadcastRaw(b []byte) {
	c.rawMu.Lock()
	if len(c.rawSubs) == 0 {
		c.rawMu.Unlock()
		return
	}
	// Copy once so each callback receives a stable slice; the pump reuses buf.
	data := append([]byte(nil), b...)
	subs := make([]func([]byte), 0, len(c.rawSubs))
	for _, fn := range c.rawSubs {
		subs = append(subs, fn)
	}
	c.rawMu.Unlock()
	for _, fn := range subs {
		fn(data)
	}
}
