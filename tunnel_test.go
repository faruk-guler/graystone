package main

import (
	"context"
	"errors"
	"io"
	"net"
	"runtime/debug"
	"sync"
	"testing"
	"time"

	"gravel/internal/app"
	"gravel/internal/sessionstore"
	"gravel/internal/sshclient"
)

// Stopped tunnels hold a nil listener. These tests guard two regressions:
// CloseSession / shutdown / CloseTunnel calling Close on that nil interface and
// panicking, and Stop deleting the definition so the user had to retype it.

func newTunnelApp(t *testing.T) (*App, *tunnel, int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	port := ln.Addr().(*net.TCPAddr).Port
	a := NewApp()
	tr := &tunnel{ID: "t1", SessionID: "s1", Name: "demo", LocalPort: port, RemoteHost: "db.internal", RemotePort: 5432, listener: ln}
	a.tunnels[tr.ID] = tr
	return a, tr, port
}

func TestStopTunnelKeepsTheDefinition(t *testing.T) {
	a, tr, _ := newTunnelApp(t)

	if !tr.running() {
		t.Fatal("precondition: tunnel should start out running")
	}
	if err := a.StopTunnel(tr.ID); err != nil {
		t.Fatalf("StopTunnel: %v", err)
	}
	if _, ok := a.tunnels[tr.ID]; !ok {
		t.Fatal("StopTunnel must keep the definition so the row survives")
	}
	if tr.running() {
		t.Fatal("tunnel should report stopped")
	}
	if err := a.StopTunnel(tr.ID); err != nil {
		t.Fatalf("second StopTunnel: %v", err)
	}

	list := a.ListTunnels()
	if len(list) != 1 {
		t.Fatalf("ListTunnels returned %d entries, want 1", len(list))
	}
	if list[0].Running {
		t.Fatal("ListTunnels should report the tunnel as stopped")
	}
	if list[0].LocalPort != tr.LocalPort || list[0].RemoteHost != "db.internal" || list[0].RemotePort != 5432 {
		t.Fatalf("stopped tunnel lost its parameters: %+v", list[0])
	}
}

func TestCloseTunnelOnStoppedTunnelDoesNotPanic(t *testing.T) {
	a, tr, _ := newTunnelApp(t)
	if err := a.StopTunnel(tr.ID); err != nil {
		t.Fatalf("StopTunnel: %v", err)
	}
	if err := a.CloseTunnel(tr.ID); err != nil {
		t.Fatalf("CloseTunnel on a stopped tunnel: %v", err)
	}
	if _, ok := a.tunnels[tr.ID]; ok {
		t.Fatal("CloseTunnel must remove the definition")
	}
	if err := a.CloseTunnel(tr.ID); err == nil {
		t.Fatal("CloseTunnel on a missing id should report an error")
	}
}

func TestCloseSessionClosesStoppedTunnels(t *testing.T) {
	a, tr, _ := newTunnelApp(t)
	if err := a.StopTunnel(tr.ID); err != nil {
		t.Fatalf("StopTunnel: %v", err)
	}
	sid := tr.SessionID
	ctrl := app.New(sessionstore.Profile{}, sshclient.Credential{}, nil, nil)
	a.sessions[sid] = &appSession{ID: sid, Ctrl: ctrl}
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("CloseSession panicked on a stopped tunnel: %v\n%s", r, debug.Stack())
		}
	}()
	a.CloseSession(sid)
	// The tunnel row must survive as an orphan so the user still sees it.
	list := a.ListTunnels()
	if len(list) != 1 {
		t.Fatalf("CloseSession must keep tunnel definitions; got %d rows", len(list))
	}
	if list[0].Running {
		t.Fatal("CloseSession must close the listener")
	}
	if !list[0].Orphaned {
		t.Fatal("a tunnel whose session is gone must report orphaned")
	}
}

// TestCloseSessionOrphansARunningTunnel pins the new CloseSession behaviour:
// a running tunnel is not deleted; its listener is closed and SessionID cleared
// so the row shows "orphaned" until a new session to the same server arrives.
func TestCloseSessionOrphansARunningTunnel(t *testing.T) {
	a, tr, _ := newTunnelApp(t)
	// tr is running (newTunnelApp gives it a live listener).
	sid := tr.SessionID
	ctrl := app.New(sessionstore.Profile{}, sshclient.Credential{}, nil, nil)
	a.sessions[sid] = &appSession{ID: sid, Ctrl: ctrl}

	a.CloseSession(sid)

	if tr.running() {
		t.Fatal("CloseSession must release the listener")
	}
	if tr.SessionID != "" {
		t.Fatalf("CloseSession must clear SessionID; got %q", tr.SessionID)
	}
	list := a.ListTunnels()
	if len(list) != 1 {
		t.Fatalf("running tunnel must survive CloseSession; got %d rows", len(list))
	}
	if !list[0].Orphaned {
		t.Fatal("orphaned tunnel must report Orphaned=true")
	}
}

// TestStartTunnelWithoutSessionKeepsDefinition pins the guard behind a row whose
// session is gone: starting it can only fail, and the failure has to leave the
// definition in place rather than panic or drop the row.
func TestStartTunnelWithoutSessionKeepsDefinition(t *testing.T) {
	a, tr, _ := newTunnelApp(t)
	if err := a.StopTunnel(tr.ID); err != nil {
		t.Fatalf("StopTunnel: %v", err)
	}
	tr.SessionID = ""
	if err := a.StartTunnel(tr.ID); err == nil {
		t.Fatal("starting a forward with no session behind it must fail")
	}
	if _, ok := a.tunnels[tr.ID]; !ok {
		t.Fatal("a failed start must still keep the definition")
	}
	if tr.running() {
		t.Fatal("a forward that could not be re-bound must stay stopped")
	}
}

// TestValidForwardHost pins the destination rule the tunnel forms and the stored
// definitions are both held to. The case it exists for is "442": a port typed
// into the host box is a legal DNS label, so without the explicit check a forward
// that can never carry traffic would sit in the table reading "running".
func TestValidForwardHost(t *testing.T) {
	good := []string{"10.0.0.5", "127.0.0.1", "::1", "fe80::1", "db.internal", "localhost", "web-1.example.com", "  10.0.0.5  "}
	for _, h := range good {
		if err := validForwardHost(h); err != nil {
			t.Errorf("validForwardHost(%q) = %v, want nil", h, err)
		}
	}
	bad := []string{"", "   ", "442", "8080", "http://db.internal", "db internal", "[db.internal]:5432", "db:", "db..internal", "-db"}
	for _, h := range bad {
		if err := validForwardHost(h); err == nil {
			t.Errorf("validForwardHost(%q) = nil, want an error", h)
		}
	}
}

// TestStartTunnelRefusesAnUnusableDestination keeps a definition saved by an
// earlier build - or hand-edited into tunnels.json - from opening a listener on a
// destination that cannot be dialled. The row has to read stopped, with the reason
// in the log, rather than running over a dead path.
func TestStartTunnelRefusesAnUnusableDestination(t *testing.T) {
	a, tr, _ := newTunnelApp(t)
	tr.RemoteHost = "442"
	if err := a.StopTunnel(tr.ID); err != nil {
		t.Fatalf("StopTunnel: %v", err)
	}
	if err := a.StartTunnel(tr.ID); err == nil {
		t.Fatal("a forward whose destination is a number must not start")
	}
	if tr.running() {
		t.Fatal("a refused start must leave the forward stopped")
	}
	if _, ok := a.tunnels[tr.ID]; !ok {
		t.Fatal("a refused start must keep the definition")
	}
}

// TestUpdateTunnelRejectsBadInputWithoutBreakingAWorkingForward pins the order of
// operations in UpdateTunnel: an invalid edit has to fail while the forward that
// is carrying traffic stays up. Validating only after StopTunnel used to leave
// the user with a stopped tunnel, changed settings and no replacement.
func TestUpdateTunnelRejectsBadInputWithoutBreakingAWorkingForward(t *testing.T) {
	a, tr, port := newTunnelApp(t)

	cases := []struct {
		desc   string
		local  int
		host   string
		remote int
	}{
		{"zero local port", 0, tr.RemoteHost, tr.RemotePort},
		{"local port above the range", 70000, tr.RemoteHost, tr.RemotePort},
		{"negative local port", -1, tr.RemoteHost, tr.RemotePort},
		{"zero remote port on a local forward", port, tr.RemoteHost, 0},
		{"empty destination host", port, "", tr.RemotePort},
		{"a port typed into the host box", port, "442", tr.RemotePort},
		{"a pasted URL as the host", port, "http://db.internal", tr.RemotePort},
	}
	for _, c := range cases {
		if _, err := a.UpdateTunnel(tr.ID, "demo", c.local, c.host, c.remote, "local"); err == nil {
			t.Fatalf("%s: UpdateTunnel should report an error", c.desc)
		}
		if !tr.running() {
			t.Fatalf("%s: a rejected edit stopped the working forward", c.desc)
		}
		if tr.LocalPort != port || tr.RemotePort != 5432 || tr.RemoteHost != "db.internal" {
			t.Fatalf("%s: a rejected edit rewrote the definition: %+v", c.desc, tr)
		}
	}
}

// blockingDialer never answers: it returns only once the caller's context is
// done, which is how a target that swallows packets rather than refusing them
// behaves behind the SSH link.
type blockingDialer struct {
	entered chan struct{}
	once    sync.Once
}

func (d *blockingDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	d.once.Do(func() { close(d.entered) })
	<-ctx.Done()
	return nil, ctx.Err()
}

// TestDialBoundedGivesUpOnAStuckTarget: both -L and -D forwards can be bound to
// the LAN, so every accepted client that aims at a black-holed destination used
// to park a goroutine - and an SSH channel request - for the lifetime of the
// session.
func TestDialBoundedGivesUpOnAStuckTarget(t *testing.T) {
	old := tunnelDialTimeout
	tunnelDialTimeout = 80 * time.Millisecond
	defer func() { tunnelDialTimeout = old }()

	d := &blockingDialer{entered: make(chan struct{})}
	done := make(chan error, 1)
	go func() {
		_, err := dialBounded(d, "tcp", "203.0.113.1:22")
		done <- err
	}()

	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("dialBounded returned %v, want a deadline error", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("dialBounded never gave up on the stuck target")
	}
	select {
	case <-d.entered:
	default:
		t.Fatal("the dial was never attempted")
	}
}

// TestDialBoundedPassesThroughAFastTarget keeps the other side of that contract:
// the helper must add a budget, not behaviour - the target's own error still
// reaches the caller untouched.
func TestDialBoundedPassesThroughAFastTarget(t *testing.T) {
	want := errors.New("connection refused by the target")
	d := funcDialer{fn: func(ctx context.Context, network, addr string) (net.Conn, error) {
		if _, ok := ctx.Deadline(); !ok {
			t.Error("dialBounded must put a deadline on the context")
		}
		if network != "tcp" || addr != "db.internal:5432" {
			t.Errorf("dial args = %q %q, want tcp db.internal:5432", network, addr)
		}
		return nil, want
	}}

	if _, err := dialBounded(d, "tcp", "db.internal:5432"); !errors.Is(err, want) {
		t.Fatalf("dialBounded error = %v, want the target's own %v", err, want)
	}
}

// funcDialer adapts a plain function to the sshDialer interface.
type funcDialer struct {
	fn func(ctx context.Context, network, addr string) (net.Conn, error)
}

func (d funcDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return d.fn(ctx, network, addr)
}

func TestValidPortAcceptsRealPorts(t *testing.T) {
	for _, p := range []int{1, 22, 1080, 65535} {
		if err := validPort("local", p); err != nil {
			t.Fatalf("validPort(%d) = %v, want nil", p, err)
		}
	}
	for _, p := range []int{-1, 0, 65536} {
		if err := validPort("local", p); err == nil {
			t.Fatalf("validPort(%d) = nil, want an error", p)
		}
	}
}

func TestUpdateTunnelUnknownIDFails(t *testing.T) {
	a, _, _ := newTunnelApp(t)
	if _, err := a.UpdateTunnel("missing", "x", 8080, "h", 80, "local"); err == nil {
		t.Fatal("editing a tunnel that does not exist should fail")
	}
}

func TestTunnelAddressesDerivedFromParts(t *testing.T) {
	tr := &tunnel{LocalPort: 3131, RemoteHost: "192.168.45.44", RemotePort: 75}
	if got, want := tr.localAddr(), "127.0.0.1:3131"; got != want {
		t.Fatalf("localAddr() = %q, want %q", got, want)
	}
	if info := tunnelInfo(tr); info.Bind != "local" {
		t.Fatalf("default bind = %q, want local", info.Bind)
	}
	// A LAN-bound tunnel listens on every interface and says so in its row.
	lan := &tunnel{LocalPort: 1080, bindAll: true, dynamic: true}
	if got, want := lan.localAddr(), "0.0.0.0:1080"; got != want {
		t.Fatalf("LAN localAddr() = %q, want %q", got, want)
	}
	if info := tunnelInfo(lan); info.Bind != "lan" {
		t.Fatalf("lan bind = %q, want lan", info.Bind)
	}
	if got, want := lan.remoteAddr(), ""; got != want {
		t.Fatalf("dynamic remoteAddr() = %q, want %q", got, want)
	}
	if got, want := tr.remoteAddr(), "192.168.45.44:75"; got != want {
		t.Fatalf("remoteAddr() = %q, want %q", got, want)
	}
	info := tunnelInfo(tr)
	if info.LocalPort != 3131 || info.RemoteHost != "192.168.45.44" || info.RemotePort != 75 {
		t.Fatalf("TunnelInfo lost the parts: %+v", info)
	}
	if info.Type != tunnelTypeLocal {
		t.Fatalf("TunnelInfo.Type = %q, want %q", info.Type, tunnelTypeLocal)
	}
	if info.Running {
		t.Fatal("a tunnel with no listener must not report running")
	}
}

// TestRemoteTunnelHelpers pins the reverse (-R) field semantics: the server
// opens RemoteHost:RemotePort and each connection lands on this machine's
// 127.0.0.1:LocalPort, so serverBindAddr/localTarget read those roles back and
// an empty server host renders as localhost rather than a bare ":port".
func TestRemoteTunnelHelpers(t *testing.T) {
	r := &tunnel{LocalPort: 8080, RemoteHost: "", RemotePort: 2222, remote: true}
	if got, want := r.kind(), "remote"; got != want {
		t.Fatalf("kind() = %q, want %q", got, want)
	}
	if got, want := r.typeName(), tunnelTypeRemote; got != want {
		t.Fatalf("typeName() = %q, want %q", got, want)
	}
	if got, want := r.serverBindAddr(), ":2222"; got != want {
		t.Fatalf("serverBindAddr() = %q, want %q", got, want)
	}
	if got, want := r.localTarget(), "127.0.0.1:8080"; got != want {
		t.Fatalf("localTarget() = %q, want %q", got, want)
	}
	if got, want := r.remoteAddr(), "localhost:2222"; got != want {
		t.Fatalf("remoteAddr() with empty host = %q, want %q", got, want)
	}
	// A named server bind host is passed through to both the listen call and
	// the display string.
	r2 := &tunnel{LocalPort: 8080, RemoteHost: "0.0.0.0", RemotePort: 2222, remote: true}
	if got, want := r2.serverBindAddr(), "0.0.0.0:2222"; got != want {
		t.Fatalf("serverBindAddr() = %q, want %q", got, want)
	}
	if got, want := r2.remoteAddr(), "0.0.0.0:2222"; got != want {
		t.Fatalf("remoteAddr() = %q, want %q", got, want)
	}
	// The row's "all interfaces" choice (PuTTY's "remote ports do the same") is the
	// same request spelled without typing an address: the listen call has to name
	// every interface, and the row has to say so rather than claim loopback.
	r3 := &tunnel{LocalPort: 8080, RemoteHost: "", RemotePort: 2222, remote: true, bindAll: true}
	if got, want := r3.serverBindAddr(), "0.0.0.0:2222"; got != want {
		t.Fatalf("serverBindAddr() with bindAll = %q, want %q", got, want)
	}
	if got, want := r3.remoteAddr(), "0.0.0.0:2222"; got != want {
		t.Fatalf("remoteAddr() with bindAll = %q, want %q", got, want)
	}
	if got := tunnelInfo(r3).Bind; got != "lan" {
		t.Fatalf("tunnelInfo().Bind = %q, want %q", got, "lan")
	}
	if info := tunnelInfo(r); info.Kind != "remote" || info.Type != tunnelTypeRemote {
		t.Fatalf("tunnelInfo lost the remote shape: %+v", info)
	}
}

// TestForwardLocalRelaysBothDirections proves the reverse relay's job without an
// SSH server: a connection handed back from the server side is dialled to the
// local target and pumped in both directions until either end closes.
func TestForwardLocalRelaysBothDirections(t *testing.T) {
	// A local echo service stands in for the 127.0.0.1 target the -R forward
	// is pointed at.
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen echo: %v", err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { _, _ = io.Copy(c, c); _ = c.Close() }(c)
		}
	}()

	// net.Pipe gives us the two ends of the tunneled connection: forwardLocal
	// owns remoteEnd (as if x/crypto had handed it up from the server), and the
	// test speaks as the remote client on clientEnd.
	remoteEnd, clientEnd := net.Pipe()
	defer clientEnd.Close()
	a := NewApp()
	go a.forwardLocal(remoteEnd, echo.Addr().String())

	if err := clientEnd.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	if _, err := clientEnd.Write([]byte("hello -R")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 8)
	if _, err := io.ReadFull(clientEnd, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf) != "hello -R" {
		t.Fatalf("echoed %q, want %q", buf, "hello -R")
	}
}

// ---------- tunnel persistence (tunnels.json) ----------

// newStoredApp returns an App backed by a real store in a fresh temp folder,
// which is what the persist/restore paths need. startup() is not run (it wants
// a Wails context), so the store is installed directly.
func newStoredApp(t *testing.T) *App {
	t.Helper()
	a, _ := newStoredAppIn(t, t.TempDir())
	return a
}

// newStoredAppIn does the same against a caller-owned folder, so a test can
// build a second store over the same directory and prove the file re-reads.
func newStoredAppIn(t *testing.T, dir string) (*App, string) {
	t.Helper()
	a := NewApp()
	st := sessionstore.NewStore(dir)
	if err := st.Load(); err != nil {
		t.Fatalf("store load: %v", err)
	}
	if err := st.LoadTunnels(); err != nil {
		t.Fatalf("tunnels load: %v", err)
	}
	a.store = st
	return a, dir
}

// listeningTunnel puts a live local forward into a (not yet persisted) row.
func listeningTunnel(t *testing.T, a *App, profileAddr string) *tunnel {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	tr := &tunnel{
		ID: "t1", SessionID: "s1", Name: "db", listener: ln,
		LocalPort:  ln.Addr().(*net.TCPAddr).Port,
		RemoteHost: "db.internal", RemotePort: 5432,
		profileAddr: profileAddr, autoStart: true,
	}
	a.mu.Lock()
	a.tunnels[tr.ID] = tr
	a.mu.Unlock()
	return tr
}

func TestPersistTunnelSurvivesAReload(t *testing.T) {
	a, dir := newStoredAppIn(t, t.TempDir())
	tr := listeningTunnel(t, a, "10.0.0.1:22")

	a.persistTunnel(tr)
	if tr.defID == "" {
		t.Fatal("persistTunnel must record the allocated definition id on the row")
	}
	defs := a.store.TunnelsForProfile("10.0.0.1:22")
	if len(defs) != 1 {
		t.Fatalf("TunnelsForProfile = %d defs, want 1", len(defs))
	}
	got := defs[0]
	if got.ID != tr.defID || got.Name != "db" || got.LocalPort != tr.LocalPort ||
		got.RemoteHost != "db.internal" || got.RemotePort != 5432 || !got.AutoStart {
		t.Fatalf("persisted definition lost fields: %+v", got)
	}

	// A second persist of the same row must update, not pile up a duplicate.
	a.mu.Lock()
	tr.Name = "db-renamed"
	a.mu.Unlock()
	a.persistTunnel(tr)
	if again := a.store.TunnelsForProfile("10.0.0.1:22"); len(again) != 1 || again[0].Name != "db-renamed" {
		t.Fatalf("re-persist duplicated or lost the row: %+v", again)
	}
	if again := a.store.TunnelsForProfile("10.0.0.1:22"); again[0].ID != tr.defID {
		t.Fatal("re-persist must keep the same definition id")
	}

	// And the file has to be readable by a fresh store: that is the whole point
	// of persisting at all.
	reloaded := sessionstore.NewStore(dir)
	if err := reloaded.LoadTunnels(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if list := reloaded.TunnelsForProfile("10.0.0.1:22"); len(list) != 1 || list[0].Name != "db-renamed" {
		t.Fatalf("reload lost the definition: %+v", list)
	}
}

func TestCloseSessionKeepsThePersistedDefinition(t *testing.T) {
	a := newStoredApp(t)
	tr := listeningTunnel(t, a, "10.0.0.1:22")
	a.persistTunnel(tr)
	ctrl := app.New(sessionstore.Profile{}, sshclient.Credential{}, nil, nil)
	a.sessions[tr.SessionID] = &appSession{ID: tr.SessionID, Ctrl: ctrl}

	a.CloseSession(tr.SessionID)

	// The in-memory row is orphaned but present, and so is the one on disk.
	list := a.ListTunnels()
	if len(list) != 1 || !list[0].Orphaned || list[0].Running {
		t.Fatalf("CloseSession must leave an orphaned stopped row: %+v", list)
	}
	if defs := a.store.TunnelsForProfile("10.0.0.1:22"); len(defs) != 1 {
		t.Fatalf("CloseSession must not delete the stored definition: %+v", defs)
	}
}

func TestCloseTunnelRemovesThePersistedDefinition(t *testing.T) {
	a := newStoredApp(t)
	tr := listeningTunnel(t, a, "10.0.0.1:22")
	a.persistTunnel(tr)
	if err := a.CloseTunnel(tr.ID); err != nil {
		t.Fatalf("CloseTunnel: %v", err)
	}
	if defs := a.store.TunnelsForProfile("10.0.0.1:22"); len(defs) != 0 {
		t.Fatalf("CloseTunnel must delete the stored row: %+v", defs)
	}
	if len(a.ListTunnels()) != 0 {
		t.Fatal("CloseTunnel must delete the live row too")
	}
}

// TestAutoStartRestoresRowsWithoutAConnection covers the restore path for the
// case that needs no server: the definitions become rows again, and an
// AutoStart one that cannot bind because its session is not dialled yet stays
// stopped instead of vanishing or panicking.
func TestAutoStartRestoresRowsWithoutAConnection(t *testing.T) {
	a := newStoredApp(t)
	tr := listeningTunnel(t, a, "10.0.0.1:22")
	a.persistTunnel(tr)
	localPort := tr.LocalPort
	// Tear the session down so the row is an orphan, exactly as a logout would.
	ctrl := app.New(sessionstore.Profile{}, sshclient.Credential{}, nil, nil)
	a.sessions[tr.SessionID] = &appSession{ID: tr.SessionID, Ctrl: ctrl}
	a.CloseSession(tr.SessionID)

	// A new session id that has no controller behind it yet.
	a.autoStartTunnels("10.0.0.1:22", "newsid")

	list := a.ListTunnels()
	if len(list) != 1 {
		t.Fatalf("autoStartTunnels should leave exactly one row, got %d: %+v", len(list), list)
	}
	got := list[0]
	if got.SessionID != "newsid" {
		t.Fatalf("restored row is not attached to the new session: %+v", got)
	}
	if got.LocalPort != localPort || got.RemoteHost != "db.internal" || got.RemotePort != 5432 {
		t.Fatalf("restored row lost the stored parameters: %+v", got)
	}
	// The start could not happen (no controller for newsid), so the row reads
	// stopped and the old orphan is gone rather than duplicated.
	if got.Running {
		t.Fatal("a forward with no SSH connection behind it must stay stopped")
	}
	if got.Orphaned {
		t.Fatal("the restored row belongs to the live session, not the dead one")
	}
}

// TestAutoStartSkipsOtherProfiles keeps a tunnel defined for one server from
// being resurrected onto another, which would forward to the wrong place.
func TestAutoStartSkipsOtherProfiles(t *testing.T) {
	a := newStoredApp(t)
	tr := listeningTunnel(t, a, "10.0.0.1:22")
	a.persistTunnel(tr)

	a.autoStartTunnels("192.168.1.5:22", "elsewhere")
	// The original row for 10.0.0.1:22 stays; nothing may be attached to the
	// other session, or a tunnel would forward to the wrong server.
	for _, info := range a.ListTunnels() {
		if info.SessionID == "elsewhere" {
			t.Fatalf("a tunnel was restored for a different server: %+v", info)
		}
	}
	if n := len(a.ListTunnels()); n != 1 {
		t.Fatalf("ListTunnels = %d rows, want only the original: %+v", n, a.ListTunnels())
	}
}

// TestPersistTunnelIgnoresUnaddressedRow keeps the test fixture and the
// startup-failure path (no config dir, no store) from writing a record that
// cannot be grouped under any server.
func TestPersistTunnelIgnoresUnaddressedRow(t *testing.T) {
	a := NewApp() // no store at all: startup never ran
	tr := &tunnel{ID: "t1", SessionID: "s1", Name: "x", LocalPort: 1234}
	a.mu.Lock()
	a.tunnels[tr.ID] = tr
	a.mu.Unlock()
	a.persistTunnel(tr)
	a.removeTunnelDef(tr)
	if tr.defID != "" {
		t.Fatalf("no store means nothing was persisted, defID must stay empty: %q", tr.defID)
	}

	// With a store but no profile address the row still cannot be grouped.
	b := newStoredApp(t)
	tr2 := &tunnel{ID: "t2", SessionID: "s1", Name: "y", LocalPort: 1235}
	b.mu.Lock()
	b.tunnels[tr2.ID] = tr2
	b.mu.Unlock()
	b.persistTunnel(tr2)
	if tr2.defID != "" {
		t.Fatal("a tunnel with no profile address must not be persisted")
	}
}
