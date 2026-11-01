package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/wailsapp/wails/v2/pkg/runtime"

	"graystone/internal/app"
	"graystone/internal/follow"
	"graystone/internal/logging"
	"graystone/internal/proxydial"
	"graystone/internal/sessionstore"
	"graystone/internal/sftpclient"
	"graystone/internal/socks"
	"graystone/internal/sshclient"
	"graystone/internal/transfer"
)

// Version is the product version string surfaced to the UI.
const Version = "4.9.0"

// maxConcurrentTransfers bounds how many files move at once in the queue.
const maxConcurrentTransfers = 2

// maxDownloadFiles caps a folder download so pointing it at something like /usr
// fails with a message instead of queueing tens of thousands of transfers.
// shortcut: 2000 entries per pick, upgrade by streaming the walk into the queue
// if a real tree ever needs more than that.
const maxDownloadFiles = 2000

// maxAuthAttempts bounds the PuTTY-style re-prompt loop after a rejected
// password. Servers cap this themselves (OpenSSH MaxAuthTries defaults to 6);
// three keeps a mistyped password recoverable without letting a locked-out
// account cycle forever.
const maxAuthAttempts = 3

// keepLogs bounds how many per-launch log files stay in the config folder, so a
// long-lived install does not accumulate one for every start it ever had. The
// security value runs the other way too: these files hold connection history.
const keepLogs = 20

// App is the Wails-bound root object. Every exported method becomes callable
// from the frontend as window.go.main.App.<Method>.
type App struct {
	ctx       context.Context
	mu        sync.Mutex
	sessions  map[string]*appSession
	order     []string
	tunnels   map[string]*tunnel
	kh        *sshclient.KnownHosts
	store     *sessionstore.Store
	logger    *logging.Logger
	configDir string

	// proxyPass is the in-memory outbound-proxy password. It is never written
	// to proxy.json (only kind/host/port/user persist), matching the rule that
	// secrets are not stored on disk; a restart clears it.
	proxyPass string

	// connGen bumps with every Connect/ConnectKey so an earlier attempt that
	// is still dialling (a 5s probe timeout, a slow handshake) can tell it has
	// been superseded and stay quiet instead of splashing its FATAL ERROR onto
	// the newer attempt's login prompt.
	connGen uint64

	pendingAuth  chan string
	pendingCreds map[string]cachedCred
}

// newConnAttempt registers a connection attempt and returns its ticket.
func (a *App) newConnAttempt() uint64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.connGen++
	return a.connGen
}

// superseded reports whether a newer Connect started after this ticket.
func (a *App) superseded(gen uint64) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.connGen != gen
}

type appSession struct {
	ID        string
	Ctrl      *app.Controller
	Profile   sessionstore.Profile
	FilesPath string
	cancel    func()
	queue     *transfer.TransferQueue
	// dropped records that the link died (a keepalive teardown or a transport
	// error), as opposed to a logout or a close the user asked for. It is read
	// and written only on the exit path under a.mu, so the UI can decide
	// whether offering a reconnect even makes sense.
	dropped bool
}

type cachedCred struct {
	user string
	pass string
	at   time.Time
}

type tunnel struct {
	ID         string
	SessionID  string
	Name       string
	LocalPort  int
	RemoteHost string
	RemotePort int
	// dynamic marks a SOCKS5 (-D) forward: the remote host/port are unused
	// and each client request carries its own destination.
	// remote marks a reverse (-R) forward: the SSH server opens RemoteHost:
	// RemotePort and every connection to it is delivered back through the
	// tunnel to a service on this machine at 127.0.0.1:LocalPort. For that
	// mode LocalPort is the local target, not a local listener, and bindAll
	// is meaningless (the listening side lives on the server).
	// bindAll listens on every interface (0.0.0.0) instead of loopback, so
	// other devices on the LAN can use this tunnel too.
	dynamic bool
	remote  bool
	bindAll bool
	// profileAddr is the "host:port" key that groups this tunnel's stored
	// definition in tunnels.json. It is set when a tunnel is created from a
	// live session so auto-start can find it after a reconnect.
	profileAddr string
	// defID is the tunnels.json primary key. Empty until the first
	// persistTunnel call allocates one; it is reused for subsequent updates
	// and cleared only when the definition is explicitly removed by the user.
	defID string
	// autoStart mirrors TunnelDef.AutoStart: when true the tunnel is restarted
	// automatically each time a new session to profileAddr opens.
	autoStart bool
	listener  net.Listener
}

// running reports whether the forward is live. A nil listener means the
// definition is kept but stopped, so the row survives a Stop and can start
// again without retyping anything.
func (t *tunnel) running() bool { return t.listener != nil }

// takeListener detaches a tunnel's listener under a.mu and hands it back for
// closing outside the lock. The handover has to be inside the lock: reading
// t.listener after releasing it races StartTunnel installing a new one, and the
// row could then be deleted while its freshly bound port belongs to nobody - a
// listener no code path will ever close again.
func (a *App) takeListener(t *tunnel) net.Listener {
	a.mu.Lock()
	defer a.mu.Unlock()
	ln := t.listener
	t.listener = nil
	return ln
}

// closeListenerOf releases a tunnel's bound port. It is safe on a stopped
// forward, whose listener is nil - without the guard, closing a session that
// held a stopped tunnel would panic on the nil interface.
func (a *App) closeListenerOf(t *tunnel) error {
	if ln := a.takeListener(t); ln != nil {
		return ln.Close()
	}
	return nil
}

// localAddr and remoteAddr are the addresses actually bound locally and dialled
// through the SSH connection. The parts are stored rather than the strings so
// the UI can show and re-edit them without parsing. A dynamic forward dials no
// fixed target, so it has no remote address to name. A LAN-bound tunnel
// listens on every interface; the default stays loopback-only.
func (t *tunnel) localAddr() string {
	host := "127.0.0.1"
	if t.bindAll {
		host = "0.0.0.0"
	}
	return fmt.Sprintf("%s:%d", host, t.LocalPort)
}
func (t *tunnel) remoteAddr() string {
	if t.dynamic {
		return ""
	}
	if t.remote && t.RemoteHost == "" {
		// No bind host named: either the server's own default (loopback), or every
		// interface when the row asked for PuTTY's "remote ports do the same".
		// Naming that keeps the log and the row honest about what was requested.
		if t.bindAll {
			return "0.0.0.0:" + strconv.Itoa(t.RemotePort)
		}
		return "localhost:" + strconv.Itoa(t.RemotePort)
	}
	return fmt.Sprintf("%s:%d", t.RemoteHost, t.RemotePort)
}

// serverBindAddr is the address the SSH server listens on for a reverse (-R)
// forward. An empty host is passed through as ":port", which the server binds
// to its default (loopback unless GatewayPorts allows otherwise).
func (t *tunnel) serverBindAddr() string {
	host := t.RemoteHost
	if host == "" && t.bindAll {
		// The row chose "every interface" instead of the server's loopback default.
		// sshd only grants this with GatewayPorts set to clientspecified or yes; a
		// refusal comes back from client.Listen as an error the row then reports.
		host = "0.0.0.0"
	}
	return net.JoinHostPort(host, strconv.Itoa(t.RemotePort))
}

// localTarget is where a reverse (-R) forward delivers each tunneled
// connection on this machine: the loopback service the user pointed at.
func (t *tunnel) localTarget() string {
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(t.LocalPort))
}

// kind is the machine-readable tunnel type the frontend branches on.
func (t *tunnel) kind() string {
	switch {
	case t.dynamic:
		return "dynamic"
	case t.remote:
		return "remote"
	}
	return "local"
}

// tunnelTypeLocal names a fixed local forward, shown in the Type column so the
// table reads the same way as the others do.
const tunnelTypeLocal = "Local (-L)"

// tunnelTypeDynamic names a SOCKS5 forward: any destination, chosen per request
// by whatever client connects to the local port.
const tunnelTypeDynamic = "Dynamic (SOCKS)"

// tunnelTypeRemote names a reverse forward: the server opens a port and hands
// each connection back through the tunnel to a local service.
const tunnelTypeRemote = "Remote (-R)"

// typeName is the display label for the Type column.
func (t *tunnel) typeName() string {
	switch {
	case t.dynamic:
		return tunnelTypeDynamic
	case t.remote:
		return tunnelTypeRemote
	}
	return tunnelTypeLocal
}

// validPort guards a port the user typed. Left unchecked, a zero local port
// makes net.Listen pick an ephemeral port and the row then advertises a port it
// does not actually hold; a zero remote port only fails later, on every
// connection attempt, with a message that does not point back at the form.
func validPort(kind string, port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("%s port %d out of range (1-65535)", kind, port)
	}
	return nil
}

// forwardHostRE accepts a DNS name as a sequence of RFC 1123 labels. Addresses
// are handled separately by net.ParseIP, so what this rejects is the residue of
// pasting a URL or a "[host]:port" pair: spaces, slashes, brackets, a trailing
// colon, an empty label.
var forwardHostRE = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$`)

// validForwardHost refuses a destination that can never work. The case it exists
// for is a port typed into the host box ("442"): that is a syntactically legal
// DNS label, so a bare format check lets it through, and the forward then reports
// "running" while every connection through it fails - a tunnel that looks healthy
// and is not. An IPv4 or IPv6 literal is always accepted, and so is any name
// carrying a letter; a single all-digit label is not a host.
func validForwardHost(host string) error {
	h := strings.TrimSpace(host)
	if h == "" {
		return fmt.Errorf("destination host required")
	}
	if net.ParseIP(h) != nil {
		return nil
	}
	if !forwardHostRE.MatchString(h) {
		return fmt.Errorf("destination host %q is not a valid name or address", h)
	}
	if !strings.Contains(h, ".") && strings.IndexFunc(h, unicode.IsLetter) < 0 {
		return fmt.Errorf("destination host %q looks like a port, not a host", h)
	}
	return nil
}

// NewApp creates the App instance.
func NewApp() *App {
	return &App{
		sessions:     map[string]*appSession{},
		order:        []string{},
		tunnels:      map[string]*tunnel{},
		pendingCreds: map[string]cachedCred{},
		logger:       logging.NewLogger(),
	}
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	dir, err := sessionstore.DefaultDir()
	if err != nil {
		// Without a config folder there is no store, no known hosts and no log
		// file. Say so in the in-memory ring so the Logs tab shows the reason
		// every connection fails instead of the app looking quietly broken.
		a.log("startup failed: config directory unavailable: %v", err)
		return
	}
	kh := sshclient.NewKnownHosts(dir)
	kh.Interactive = true
	if err := kh.Load(); err != nil {
		// The file has already been moved aside by Load, so this launch cannot
		// overwrite it - but the user must still learn that their trusted keys
		// list did not survive, or every "unknown host" prompt looks like the
		// app forgetting.
		a.log("trusted host keys unusable, starting with none: %v", err)
	}
	a.kh = kh
	st := sessionstore.NewStore(dir)
	if err := st.Load(); err != nil {
		a.log("saved servers unusable, starting with none: %v", err)
	}
	if err := st.LoadTunnels(); err != nil {
		a.log("saved tunnels unusable, starting with none: %v", err)
	}
	a.store = st
	a.configDir = dir
	// One log file per app launch (graystone-2006-01-02-150405.log) instead of
	// one ever-growing graystone.log; the timestamped name is the file's own
	// session header on disk.
	logName := "graystone-" + time.Now().Format("2006-01-02-150405") + ".log"
	_ = a.logger.Start(filepath.Join(dir, logName))
	// One file per launch adds up without bound, so trim the oldest ones. The
	// file just opened is the newest of them all, so this launch's log is never a
	// candidate, and only the app's own timestamped logs - under this name and the
	// names before it - are considered.
	if removed, err := sessionstore.PruneLogs(dir, keepLogs); err != nil {
		a.log("log cleanup skipped: %v", err)
	} else if removed > 0 {
		a.log("pruned %d older log file(s), keeping the newest %d", removed, keepLogs)
	}
	// Mirror every log line to the UI so the Logs tab follows along live.
	a.logger.OnLine(func(line string) { runtime.EventsEmit(a.ctx, "log:line", line) })
	a.log("startup; config dir=%s", dir)
}

func (a *App) shutdown(_ context.Context) {
	a.log("shutdown")
	a.mu.Lock()
	list := make([]*appSession, 0, len(a.sessions))
	for _, s := range a.sessions {
		list = append(list, s)
	}
	tunnels := make([]*tunnel, 0, len(a.tunnels))
	for _, t := range a.tunnels {
		tunnels = append(tunnels, t)
	}
	a.sessions = map[string]*appSession{}
	a.order = nil
	a.tunnels = map[string]*tunnel{}
	a.mu.Unlock()
	for _, t := range tunnels {
		_ = a.closeListenerOf(t)
	}
	for _, s := range list {
		if s.cancel != nil {
			s.cancel()
		}
		_ = s.Ctrl.Close()
	}
	a.logger.Stop()
}

func (a *App) log(format string, args ...interface{}) {
	if a.logger != nil {
		a.logger.Write(fmt.Sprintf(format, args...))
	}
}

// VersionInfo returns the bare product version for the About screen's
// "Version:" row; the h1 heading keeps showing just the name.
func (a *App) VersionInfo() string { return Version }

// ListLogs returns the buffered application log lines (oldest first) for the
// Logs tab. They are the same entries written to this launch's graystone-*.log.
func (a *App) ListLogs() []string {
	if a.logger == nil {
		return nil
	}
	return a.logger.Lines()
}

// LogUI records a frontend feedback line ("saved", "tunnel updated", errors)
// in the application log, so the Logs tab has a single source for every line
// it shows and Dump exports the same set the user saw on screen.
func (a *App) LogUI(text string) {
	a.log("%s", text)
}

// DumpLogs saves the buffered log lines - everything this session has sent to
// the Logs tab, up to the logger's 500-line ring - to a file the user picks.
// The per-launch file in AppData keeps recording regardless; this is a copy.
// Returns "" when the dialog is cancelled.
func (a *App) DumpLogs() (string, error) {
	if a.logger == nil {
		return "", fmt.Errorf("logger unavailable")
	}
	dest, err := runtime.SaveFileDialog(a.ctx, runtime.SaveDialogOptions{
		Title:           "Dump current session logs",
		DefaultFilename: time.Now().Format("graystone-dump-2006-01-02-1504") + ".log",
		Filters: []runtime.FileFilter{
			{DisplayName: "Log files (*.log)", Pattern: "*.log"},
			{DisplayName: "All files", Pattern: "*.*"},
		},
	})
	if err != nil || dest == "" {
		return "", err
	}
	lines := a.logger.Lines()
	data := []byte(strings.Join(lines, "\n") + "\n")
	if err := os.WriteFile(dest, data, 0o600); err != nil {
		a.log("log dump to %s failed: %v", dest, err)
		return "", err
	}
	a.log("logs dumped to %s (%d lines)", dest, len(lines))
	return dest, nil
}

// ---------- settings ----------

// prefsFile is the path of the pinned UI preferences inside the config dir.
// The live copy of these settings is the webview's localStorage, which lives
// inside the EBWebView profile folder and has been lost before: a rebuild under
// a new file name moves the executable and its profile with it, and any "clear
// site data" takes the theme, the font size and the pane width down with it.
// settings.json, written only when the user pins the settings, sits beside
// sessions.json instead.
func (a *App) prefsFile() string { return filepath.Join(a.configDir, "settings.json") }

// prefPrefix namespaces the pinned preference keys. They are the frontend's
// localStorage keys, so both sides state the same string.
const prefPrefix = "graystone."

// prefNames are the settings that may be pinned.
var prefNames = []string{
	"theme",
	"termFontSize",
	"followTerminalFolder",
	"showHidden",
	"paneWidth",
	"autoReconnect",
	"conflictPolicy",
}

// prefKeys is the whitelist of settings that may be pinned. Only these reach the
// file, so a tampered-with webview cannot use the config directory to pile up
// arbitrary keys; everything else in the payload is dropped. It is built from
// prefNames so the prefix and the list are each stated once.
var prefKeys = func() map[string]bool {
	m := make(map[string]bool, len(prefNames))
	for _, n := range prefNames {
		m[prefPrefix+n] = true
	}
	return m
}()

// prefValueMax bounds one stored value and maxPrefsPayload the whole request.
// Every legitimate preference is a theme name, a number or a short policy word,
// so these limits only ever reject junk.
const (
	prefValueMax    = 128
	maxPrefsPayload = 16 << 10
)

// prefValueValid is the value half of the whitelist: a length cap and no line
// breaks, so one stored setting can never become a multi-line entry.
func prefValueValid(v string) bool {
	return len(v) <= prefValueMax && !strings.ContainsAny(v, "\r\n")
}

// SavePreferences pins the UI preferences to disk so they outlive the webview
// profile. prefsJSON is the frontend's snapshot as a JSON object. An empty
// object clears the pinned copy, which is what "reset to defaults" needs: a
// reset that left the old copy behind would be undone on the next start.
func (a *App) SavePreferences(prefsJSON string) error {
	if a.configDir == "" {
		return fmt.Errorf("config directory unavailable")
	}
	if len(prefsJSON) > maxPrefsPayload {
		return fmt.Errorf("preferences payload too large")
	}
	var in map[string]string
	if strings.TrimSpace(prefsJSON) != "" {
		if err := json.Unmarshal([]byte(prefsJSON), &in); err != nil {
			return fmt.Errorf("bad preferences payload: %w", err)
		}
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		if !prefKeys[k] || !prefValueValid(v) {
			continue
		}
		out[k] = v
	}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	if err := sessionstore.WriteAtomic(a.prefsFile(), data); err != nil {
		return err
	}
	a.log("settings copy saved (%d of %d keys kept)", len(out), len(in))
	return nil
}

// GetPreferences returns the pinned preferences. A missing file is an empty
// map - nothing has been pinned yet - and an unreadable one is moved aside the
// way every other config file is, so the next save cannot overwrite the only
// copy of what the user had.
func (a *App) GetPreferences() map[string]string {
	empty := map[string]string{}
	if a.configDir == "" {
		return empty
	}
	data, err := os.ReadFile(a.prefsFile())
	if err != nil {
		return empty
	}
	var stored map[string]string
	if err := json.Unmarshal(data, &stored); err != nil {
		if moved := sessionstore.Quarantine(a.prefsFile()); moved != "" {
			a.log("settings copy unreadable, moved aside to %s: %v", moved, err)
		} else {
			a.log("settings copy unreadable: %v", err)
		}
		return empty
	}
	if stored == nil {
		return empty
	}
	return stored
}

// ---------- interactive auth ----------

func (a *App) promptAuth(question string, echo bool) (string, error) {
	ch := make(chan string, 1)
	a.mu.Lock()
	if a.pendingAuth != nil {
		a.mu.Unlock()
		return "", fmt.Errorf("another auth prompt is active")
	}
	a.pendingAuth = ch
	a.mu.Unlock()

	runtime.EventsEmit(a.ctx, "auth:prompt", map[string]any{"question": question, "echo": echo})

	// No deadline here. The next Connect reclaims an abandoned slot
	// (cancelStaleAuth), so a timeout would only drop a login on somebody who
	// stepped away mid-password - and it would bound the answer to a server's
	// extra 2FA question, which a human answers at human speed. At most one
	// half-dialled attempt waits, and the next connect releases it.
	ans := <-ch
	a.clearAuthSlot(ch)
	return ans, nil
}

// clearAuthSlot releases the prompt slot only if it still belongs to ch. A
// cancelled or timed-out prompt must not wipe the channel a newer attempt has
// already installed, or that attempt's question could never be answered.
func (a *App) clearAuthSlot(ch chan string) {
	a.mu.Lock()
	if a.pendingAuth == ch {
		a.pendingAuth = nil
	}
	a.mu.Unlock()
}

// noticeAuth writes an authentication status line straight into the terminal,
// outside the question/answer cycle. A rejected password has to be visible
// where the user is looking, not only in the log.
func (a *App) noticeAuth(text string) {
	a.log("%s", text)
	runtime.EventsEmit(a.ctx, "auth:notice", text)
}

// AuthAnswer delivers the user's response to the currently active auth prompt.
func (a *App) AuthAnswer(answer string) {
	a.mu.Lock()
	ch := a.pendingAuth
	a.mu.Unlock()
	if ch != nil {
		select {
		case ch <- answer:
		default:
		}
	}
}

// credential prompts for a login name and password in the terminal, in PuTTY's
// wording. A short-lived cache keyed by addr lets a TOFU retry reuse the
// just-entered credentials without re-prompting.
// shortcut: 2 minutes of re-use, upgrade if a flow needs the pair for longer.
func (a *App) credential(host, addr string) (user, pass string) {
	a.mu.Lock()
	c, ok := a.pendingCreds[addr]
	a.mu.Unlock()
	if ok && time.Since(c.at) < 2*time.Minute {
		return c.user, c.pass
	}
	u, err := a.promptAuth("login as:", true)
	if err != nil || u == "" {
		return "", ""
	}
	p, err := a.promptAuth(fmt.Sprintf("%s@%s's password:", u, host), false)
	// An empty answer is Ctrl+C or a bare Enter, and it means "give up" here too -
	// the retry loop below already treats it that way. Dialling on with a blank
	// password would burn a real attempt against the server's own limit instead of
	// stopping, which is what made a cancelled login look like it had hung.
	if err != nil || p == "" {
		return "", ""
	}
	a.mu.Lock()
	a.pendingCreds[addr] = cachedCred{user: u, pass: p, at: time.Now()}
	a.mu.Unlock()
	return u, p
}

func (a *App) clearCred(addr string) {
	a.mu.Lock()
	delete(a.pendingCreds, addr)
	a.mu.Unlock()
}

// ---------- connection proxy ----------

// ProxySettings is the persisted outbound-proxy configuration. The password is
// deliberately absent: only its presence is reported to the UI, and the secret
// itself lives in memory for the run (App.proxyPass), never on disk.
type ProxySettings struct {
	Kind        string `json:"kind"` // "" | "socks5" | "http"
	Host        string `json:"host"`
	Port        int    `json:"port"`
	User        string `json:"user"`
	HasPassword bool   `json:"hasPassword"`
}

// proxyFile is the path of the persisted proxy settings inside the config dir.
func (a *App) proxyFile() string { return filepath.Join(a.configDir, "proxy.json") }

// loadProxyConfig reads the persisted proxy settings (missing file = no proxy).
func (a *App) loadProxyConfig() ProxySettings {
	var ps ProxySettings
	if a.configDir == "" {
		return ps
	}
	data, err := os.ReadFile(a.proxyFile())
	if err != nil {
		return ps // no file yet: no proxy
	}
	if err := json.Unmarshal(data, &ps); err != nil {
		// A half-written or hand-edited file must not quietly become "no proxy",
		// because then every connection goes out direct while the user believes
		// they are routed. Move the unreadable bytes aside and say so.
		if moved := sessionstore.Quarantine(a.proxyFile()); moved != "" {
			a.log("proxy settings unreadable, moved aside to %s: %v", moved, err)
		} else {
			a.log("proxy settings unreadable, using direct connection: %v", err)
		}
		return ProxySettings{}
	}
	return ps
}

// GetProxy returns the current proxy settings for the Settings tab.
func (a *App) GetProxy() ProxySettings {
	ps := a.loadProxyConfig()
	a.mu.Lock()
	ps.HasPassword = a.proxyPass != ""
	a.mu.Unlock()
	return ps
}

// SetProxy persists the proxy kind/host/port/user. An invalid kind or a
// non-empty host with an out-of-range port is refused so a typo never leaves a
// half-configured proxy that silently breaks every connect. The password is
// never part of this call.
func (a *App) SetProxy(kind, host string, port int, user string) error {
	kind = strings.ToLower(strings.TrimSpace(kind))
	if !proxydial.ValidKind(kind) {
		return fmt.Errorf("unknown proxy kind %q", kind)
	}
	if kind != proxydial.None {
		if strings.TrimSpace(host) == "" {
			return fmt.Errorf("proxy host required")
		}
		if err := validPort("proxy", port); err != nil {
			return err
		}
	} else {
		port = 0
	}
	ps := ProxySettings{Kind: kind, Host: strings.TrimSpace(host), Port: port, User: strings.TrimSpace(user)}
	if a.configDir == "" {
		return fmt.Errorf("config directory unavailable")
	}
	data, err := json.MarshalIndent(ps, "", "  ")
	if err != nil {
		return err
	}
	if err := sessionstore.WriteAtomic(a.proxyFile(), data); err != nil {
		return err
	}
	// A changed proxy means the old in-memory password (if any) belongs to a
	// different endpoint; drop it so it is not silently reused.
	a.mu.Lock()
	a.proxyPass = ""
	a.mu.Unlock()
	a.log("proxy settings saved: kind=%s %s", kind, net.JoinHostPort(ps.Host, strconv.Itoa(ps.Port)))
	return nil
}

// SetProxyPassword stores the proxy password in memory only. It is never
// written to disk, so it must be re-entered after a restart.
func (a *App) SetProxyPassword(pass string) {
	a.mu.Lock()
	a.proxyPass = pass
	a.mu.Unlock()
	a.log("proxy password set (%d chars, in-memory only)", len(pass))
}

// proxyDialConfig builds the runtime proxy config (settings + live password)
// for a connect. Returns a zero config when no proxy is enabled.
func (a *App) proxyDialConfig() proxydial.Config {
	ps := a.loadProxyConfig()
	if ps.Kind == proxydial.None || ps.Host == "" || ps.Port <= 0 {
		return proxydial.Config{}
	}
	a.mu.Lock()
	pass := a.proxyPass
	a.mu.Unlock()
	return proxydial.Config{Kind: ps.Kind, Host: ps.Host, Port: ps.Port, User: ps.User, Pass: pass}
}

// ---------- connect ----------

// probeConnectTimeout bounds the reachability check that runs before any
// credential prompt. A refused port answers instantly; this only waits out
// firewalled addresses that swallow the SYN.
const probeConnectTimeout = 5 * time.Second

// probeReachable opens and closes a bare TCP connection to addr. PuTTY dials
// the server before it ever prints "login as:", so a machine that is down or
// has SSH switched off fails at once instead of asking for a username and
// password nobody can use. The real dial follows moments later; a server that
// dies in between is still reported by dialAndOpen.
func (a *App) probeReachable(addr string) error {
	d, err := net.DialTimeout("tcp", addr, probeConnectTimeout)
	if err != nil {
		// PuTTY words this failure "FATAL ERROR: Unable to establish connection
		// to host"; keep the same wording so it is recognisable in the terminal.
		return fmt.Errorf("FATAL ERROR: Unable to establish connection to %s", addr)
	}
	_ = d.Close()
	return nil
}

// ConnectResult is the return value of Connect/ConnectKey.
type ConnectResult struct {
	SID         string `json:"sid,omitempty"`
	Error       string `json:"error,omitempty"`
	Kind        string `json:"kind,omitempty"`
	Addr        string `json:"addr,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	KeyType     string `json:"keyType,omitempty"`
}

// cancelStaleAuth aborts a login prompt left waiting from an earlier Connect
// attempt. Without it, a fresh Connect to a dead server printed its FATAL ERROR
// straight onto the old "login as:" line and the abandoned goroutine kept the
// auth slot indefinitely - promptAuth has no deadline of its own. Releasing the
// slot here, before the caller continues, is what lets the new attempt's
// promptAuth install itself.
func (a *App) cancelStaleAuth() {
	a.mu.Lock()
	ch := a.pendingAuth
	a.pendingAuth = nil
	a.mu.Unlock()
	if ch == nil {
		return
	}
	select {
	case ch <- "":
	default:
		// An answer was already queued; the sender's Connect will observe the
		// superseded ticket before dialling.
	}
	// The blocked promptAuth takes the empty answer as a cancellation and its
	// Connect returns "cancelled"; tell the terminal to drop the prompt line too.
	runtime.EventsEmit(a.ctx, "auth:cancel", "")
}

// Connect performs a PuTTY-style interactive login (login name + password are
// prompted in the terminal; nothing is ever stored). The server is probed
// first, so a host that is down fails immediately without any prompts. A
// rejected password re-prompts for the password, keeping the login name, up to
// maxAuthAttempts.
func (a *App) Connect(host string, port int) ConnectResult {
	if port == 0 {
		port = 22
	}
	// Same rule the tunnel forms already apply: refuse before touching anything,
	// so a port no socket could bind never tears down a live login prompt on its
	// way to a dial that could only fail.
	if err := validPort("server", port); err != nil {
		a.noticeAuth(err.Error())
		return ConnectResult{Error: err.Error(), Kind: "connect"}
	}
	a.cancelStaleAuth()
	gen := a.newConnAttempt()
	addr := fmt.Sprintf("%s:%d", host, port)
	if err := a.probeReachable(addr); err != nil {
		if a.superseded(gen) {
			// A newer Connect is already on screen; log the stale failure but
			// do not write over it.
			a.log("%v (attempt superseded)", err)
			return ConnectResult{Error: "cancelled", Kind: "cancelled"}
		}
		// Show the failure where the user is looking (the terminal) as well as
		// in the status line, instead of prompting for a login nobody needs.
		a.noticeAuth(err.Error())
		return ConnectResult{Error: err.Error(), Kind: "connect"}
	}
	user, pass := a.credential(host, addr)
	if user == "" {
		a.log("connect cancelled: no credentials for %s", addr)
		return ConnectResult{Error: "cancelled", Kind: "cancelled"}
	}
	if a.superseded(gen) {
		// A newer Connect started while credentials were being typed (or served
		// from the short-lived cache); dialling now would paint its session
		// over the newer attempt's screen.
		a.log("connect %s superseded before dial", addr)
		return ConnectResult{Error: "cancelled", Kind: "cancelled"}
	}
	prof := sessionstore.Profile{ID: user + "@" + host, Name: user + "@" + host, Host: host, Port: port, User: user, Auth: sessionstore.AuthPassword}
	for attempt := 1; ; attempt++ {
		res := a.dialAndOpen(prof, sshclient.Credential{Password: pass})
		if res.Kind == "unknown_host" {
			// Leave the short-lived cache intact: the retry after the user trusts
			// the key must not ask for the login name and password again.
			return res
		}
		a.clearCred(addr)
		if res.Kind != "auth" {
			return res
		}
		if a.superseded(gen) {
			a.log("auth loop for %s abandoned: newer connect attempt", addr)
			return ConnectResult{Error: "cancelled", Kind: "cancelled"}
		}
		if attempt == maxAuthAttempts {
			a.noticeAuth("Access denied: too many incorrect passwords.")
			return ConnectResult{Error: "too many incorrect passwords", Kind: "auth"}
		}
		// Empty answer or Ctrl-C gives up rather than burning the remaining tries.
		a.noticeAuth("Access denied, please try again. (Ctrl+C gives up)")
		p, err := a.promptAuth(fmt.Sprintf("%s@%s's password:", user, host), false)
		if err != nil || p == "" {
			return ConnectResult{Error: "cancelled", Kind: "cancelled"}
		}
		pass = p
	}
}

// NewSessionLike opens another session to the same server as an existing one,
// reusing the short-lived credential cache when it is still fresh (so a quick
// duplicate often needs no re-login). It backs the tab's right-click
// "Duplicate terminal".
func (a *App) NewSessionLike(sid string) ConnectResult {
	a.mu.Lock()
	s, ok := a.sessions[sid]
	var prof sessionstore.Profile
	if ok {
		prof = s.Profile
	}
	a.mu.Unlock()
	if !ok {
		return ConnectResult{Error: "no such session", Kind: "internal"}
	}
	if prof.Auth == sessionstore.AuthKey {
		return a.ConnectKey(prof.Host, prof.Port, prof.KeyPath)
	}
	return a.Connect(prof.Host, prof.Port)
}

// ConnectKey authenticates using a private key file. The login name and the key
// passphrase are both prompted in the terminal, like Connect does - again only
// after the server proves reachable. A wrong passphrase is re-prompted up to
// maxAuthAttempts times, matching the behaviour of Connect for passwords.
func (a *App) ConnectKey(host string, port int, keyPath string) ConnectResult {
	if port == 0 {
		port = 22
	}
	if err := validPort("server", port); err != nil {
		a.noticeAuth(err.Error())
		return ConnectResult{Error: err.Error(), Kind: "connect"}
	}
	a.cancelStaleAuth()
	gen := a.newConnAttempt()
	addr := fmt.Sprintf("%s:%d", host, port)
	if err := a.probeReachable(addr); err != nil {
		if a.superseded(gen) {
			a.log("%v (attempt superseded)", err)
			return ConnectResult{Error: "cancelled", Kind: "cancelled"}
		}
		a.noticeAuth(err.Error())
		return ConnectResult{Error: err.Error(), Kind: "connect"}
	}
	user, err := a.promptAuth("login as:", true)
	if err != nil || user == "" {
		return ConnectResult{Error: "cancelled", Kind: "cancelled"}
	}
	// The error is checked here as it is at every other prompt. Dropping it made
	// a refused prompt look like "this key has no passphrase", which then burned a
	// real attempt against the server's limit on a key that only ever needed a
	// retry.
	pass, err := a.promptAuth("key passphrase (leave empty if none):", false)
	if err != nil {
		return ConnectResult{Error: "cancelled", Kind: "cancelled"}
	}
	if a.superseded(gen) {
		a.log("connect %s superseded before dial", addr)
		return ConnectResult{Error: "cancelled", Kind: "cancelled"}
	}
	prof := sessionstore.Profile{ID: user + "@" + host, Name: user + "@" + host, Host: host, Port: port, User: user, Auth: sessionstore.AuthKey, KeyPath: keyPath}
	for attempt := 1; ; attempt++ {
		res := a.dialAndOpen(prof, sshclient.Credential{Passphrase: pass})
		if res.Kind == "unknown_host" {
			return res
		}
		if res.Kind != "auth" {
			return res
		}
		if a.superseded(gen) {
			a.log("auth loop for %s abandoned: newer connect attempt", addr)
			return ConnectResult{Error: "cancelled", Kind: "cancelled"}
		}
		if attempt == maxAuthAttempts {
			a.noticeAuth("Access denied: too many incorrect passphrases.")
			return ConnectResult{Error: "too many incorrect passphrases", Kind: "auth"}
		}
		a.noticeAuth("Access denied (key passphrase), please try again. (Ctrl+C gives up)")
		p, perr := a.promptAuth("key passphrase (leave empty if none):", false)
		if perr != nil || (p == "" && attempt > 1) {
			return ConnectResult{Error: "cancelled", Kind: "cancelled"}
		}
		pass = p
	}
}

func (a *App) dialAndOpen(prof sessionstore.Profile, cred sshclient.Credential) ConnectResult {
	if a.kh == nil {
		return ConnectResult{Error: "known-hosts store unavailable", Kind: "internal"}
	}
	// Route the initial TCP through the configured outbound proxy, if any. It
	// applies to every connect; tunnels and SFTP ride the established link.
	cred.Proxy = a.proxyDialConfig()
	// Password logins carry the terminal prompt bridge into the handshake, so
	// servers that authenticate with keyboard-interactive (OTP/2FA, or
	// password-over-kbdint) can ask the user instead of rejecting a method they
	// never offered. Key logins leave it nil: a passphrase belongs to the local
	// key parse, and offering an interactive method there would let a server
	// challenge a login whose answers nobody can route back.
	if prof.Auth == sessionstore.AuthPassword {
		cred.Interact = func(question string, echo bool) (string, error) {
			return a.promptAuth(question, echo)
		}
	}
	ctrl := app.New(prof, cred, a.kh, nil)
	if err := ctrl.Connect(100, 30); err != nil {
		var unk *sshclient.UnknownHostError
		if errors.As(err, &unk) {
			a.log("unknown host %s (%s)", unk.Addr, unk.Fingerprint)
			return ConnectResult{Error: unk.Error(), Kind: "unknown_host", Addr: unk.Addr, Fingerprint: unk.Fingerprint, KeyType: unk.KeyType}
		}
		var mm *sshclient.HostKeyMismatchError
		if errors.As(err, &mm) {
			a.log("host key MISMATCH %s", mm.Addr)
			return ConnectResult{Error: mm.Error(), Kind: "host_key_mismatch", Addr: mm.Addr, Fingerprint: mm.Actual, KeyType: mm.ActualType}
		}
		// A mistyped key passphrase fails locally, before the server ever sees it,
		// but it belongs in the same in-place retry as a rejected password: the key
		// file is fine and the next typing may be the one that opens it. Any other
		// key-file failure stays a hard error - retyping cannot fix an unsupported
		// or unreadable file.
		var keyErr *sshclient.KeyFileError
		if errors.As(err, &keyErr) && errors.Is(keyErr, sshclient.ErrWrongPassphrase) {
			a.log("key passphrase rejected for %s", prof.Addr())
			return ConnectResult{Error: keyErr.Error(), Kind: "auth"}
		}
		if sshclient.AuthFailed(err) {
			// Reported separately so Connect can re-prompt instead of giving up.
			a.log("auth failed %s@%s", prof.User, prof.Addr())
			return ConnectResult{Error: err.Error(), Kind: "auth"}
		}
		a.log("connect failed %s@%s: %v", prof.User, prof.Addr(), err)
		return ConnectResult{Error: err.Error(), Kind: "connect"}
	}
	id := sessionstore.NewID()
	s := &appSession{ID: id, Ctrl: ctrl, Profile: prof, FilesPath: "/"}
	// The browser pane sits beside the terminal from the first second and the
	// shell starts in the remote home directory, so the pane begins there too:
	// a relative "cd logs" must resolve against where the user really is, not
	// against "/". SFTP is opened eagerly here (and cached by the controller),
	// which the always-visible pane needs anyway.
	if sc, err := ctrl.SFTP(); err == nil {
		s.FilesPath = sc.Home()
	}
	s.cancel = ctrl.SubscribeRaw(func(b []byte) {
		runtime.EventsEmit(a.ctx, "pty:"+id, string(b))
	})
	a.mu.Lock()
	a.sessions[id] = s
	a.order = append(a.order, id)
	a.mu.Unlock()
	// When the remote shell exits ("exit"/logout) or the link drops, tear the
	// session down and tell the UI, otherwise the tab stays on screen with a
	// dead transport behind it.
	var exitOnce sync.Once
	onExit := func() {
		exitOnce.Do(func() {
			// A controller left in StateFailed died on a transport error - a
			// reset, a keepalive teardown - not on the user's own logout, and
			// only the failed shape is worth offering a reconnect for.
			a.mu.Lock()
			s, ok := a.sessions[id]
			dropped := ctrl.State() == app.StateFailed
			if ok && dropped {
				s.dropped = true
			}
			var prof sessionstore.Profile
			if ok {
				prof = s.Profile
			}
			a.mu.Unlock()
			if !ok {
				return // CloseSession already ran (user closed this tab, app shutdown)
			}
			a.CloseSession(id)
			if dropped {
				runtime.EventsEmit(a.ctx, "session:dropped", map[string]any{
					"sid": id, "host": prof.Host, "port": prof.Port,
					"auth": string(prof.Auth), "keyPath": prof.KeyPath,
				})
				return
			}
			runtime.EventsEmit(a.ctx, "session:exit", id)
		})
	}
	ctrl.OnExit(onExit)
	// The keepalive probe gives the reason when it tears a dead link down;
	// without it the tab would vanish with only the pump's read error in the
	// log. The session is also marked dropped here: a link that died is worth
	// offering a reconnect for, a logout is not.
	ctrl.OnDeath(func(text string) {
		a.log("%s", text)
		a.markDropped(id)
		runtime.EventsEmit(a.ctx, "auth:notice", text)
	})
	if ctrl.State() != app.StateConnected {
		// The shell had already gone by the time we could subscribe.
		onExit()
		return ConnectResult{Error: "session closed immediately after connect", Kind: "connect"}
	}
	a.autoStartTunnels(prof.Addr(), id)
	a.log("connected %s@%s (sid=%s)", prof.User, prof.Addr(), id)
	return ConnectResult{SID: id}
}

// Trust records a host key fingerprint after user approval. It accepts only
// the fingerprint from the last failed attempt at that address - whether the
// store had never seen the host or saw a key that no longer matches - and a
// confirmed change replaces the stored key, the safe equivalent of removing
// the stale known_hosts line by hand.
func (a *App) Trust(addr, fingerprint string) error {
	if a.kh == nil {
		return fmt.Errorf("known-hosts store unavailable")
	}
	a.log("trusted host %s (%s)", addr, fingerprint)
	return a.kh.Trust(addr, fingerprint)
}

// markDropped flags a session's exit as a dead link rather than a logout, so
// the exit path can emit session:dropped instead of a plain session:exit.
func (a *App) markDropped(sid string) {
	a.mu.Lock()
	if s, ok := a.sessions[sid]; ok {
		s.dropped = true
	}
	a.mu.Unlock()
}

// CloseSession tears down one SSH session, stops (but keeps) its tunnels, and
// removes its transfer queue.
func (a *App) CloseSession(sid string) {
	a.mu.Lock()
	s, ok := a.sessions[sid]
	var toClose []*tunnel
	// Orphan every tunnel belonging to this session: the row stays in a.tunnels
	// so the table continues to show it, but SessionID is cleared so the
	// Start/Stop buttons become inert until a new session to the same host
	// re-claims the definition via autoStartTunnels.
	for _, t := range a.tunnels {
		if t.SessionID == sid {
			t.SessionID = ""
			toClose = append(toClose, t)
		}
	}
	if ok {
		delete(a.sessions, sid)
		for i, id := range a.order {
			if id == sid {
				a.order = append(a.order[:i], a.order[i+1:]...)
				break
			}
		}
	}
	a.mu.Unlock()
	for _, t := range toClose {
		_ = a.closeListenerOf(t)
	}
	if ok {
		if s.cancel != nil {
			s.cancel()
		}
		_ = s.Ctrl.Close()
		a.log("closed session %s", sid)
	}
}

// SessionInfo is a UI-friendly summary of one session.
type SessionInfo struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Host      string `json:"host"`
	User      string `json:"user"`
	State     string `json:"state"`
	FilesPath string `json:"filesPath"`
}

// ListSessions returns all live sessions in creation order.
func (a *App) ListSessions() []SessionInfo {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]SessionInfo, 0, len(a.order))
	for _, id := range a.order {
		s, ok := a.sessions[id]
		if !ok {
			continue
		}
		out = append(out, SessionInfo{ID: s.ID, Name: s.Profile.Name, Host: s.Profile.Addr(), User: s.Profile.User, State: s.Ctrl.State().String(), FilesPath: s.FilesPath})
	}
	return out
}

// ---------- saved server profiles ----------

// ProfileInfo is a stored server (no secrets).
type ProfileInfo struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Auth    string `json:"auth"`
	KeyPath string `json:"keyPath"`
}

// ListProfiles returns saved servers sorted by name.
func (a *App) ListProfiles() []ProfileInfo {
	if a.store == nil {
		return nil
	}
	list := a.store.List()
	out := make([]ProfileInfo, 0, len(list))
	for _, p := range list {
		out = append(out, ProfileInfo{ID: p.ID, Name: p.Name, Host: p.Host, Port: p.Port, Auth: string(p.Auth), KeyPath: p.KeyPath})
	}
	return out
}

// SaveProfile stores/updates a server profile. Login names and passwords are
// never stored; they are prompted in the terminal at connect time. Saving an
// existing name updates that row (PutNamed matches the name case-insensitively)
// instead of piling up duplicates.
func (a *App) SaveProfile(name, host string, port int, auth, keyPath string) error {
	if a.store == nil {
		return fmt.Errorf("profile store unavailable")
	}
	if name == "" {
		name = host
	}
	if port == 0 {
		port = 22
	}
	// A saved server is dialled again after a restart, so an out-of-range port
	// written here would only surface much later, in another session.
	if err := validPort("server", port); err != nil {
		a.log("profile save refused (%s): %v", name, err)
		return err
	}
	_, err := a.store.PutNamed(sessionstore.Profile{Name: name, Host: host, Port: port, Auth: sessionstore.AuthKind(auth), KeyPath: keyPath})
	if err != nil {
		a.log("profile save failed (%s): %v", name, err)
		return err
	}
	a.log("profile saved: %s (%s:%d, auth=%s)", name, host, port, auth)
	return nil
}

// DeleteProfile removes a saved server. A write failure is reported, not
// swallowed: the profile is still on disk and would reappear at the next start.
func (a *App) DeleteProfile(id string) error {
	if a.store == nil {
		return fmt.Errorf("profile store unavailable")
	}
	p, _ := a.store.Get(id)
	name := p.Name
	if name == "" {
		name = id
	}
	if err := a.store.Delete(id); err != nil {
		if errors.Is(err, sessionstore.ErrNotFound) {
			return fmt.Errorf("no such profile")
		}
		a.log("profile delete failed (%s): %v", name, err)
		return fmt.Errorf("delete %s: %w", name, err)
	}
	a.log("profile deleted: %s", name)
	return nil
}

// ImportHosts creates saved server profiles from pasted text, one host per
// line. Accepted shapes: "host", "host:port", "name host", "name,host" or
// "name=host"; an ssh:// prefix is tolerated and # lines are comments. Names
// default to the address and PutNamed keeps re-imports idempotent. It returns
// how many profiles were created or updated.
func (a *App) ImportHosts(text string) int {
	if a.store == nil {
		return 0
	}
	count := 0
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, hostport := parseImportLine(line)
		hostport = strings.TrimPrefix(strings.TrimPrefix(hostport, "ssh://"), "//")
		host, port := hostport, 22
		if h, p, err := net.SplitHostPort(hostport); err == nil {
			host = h
			if v, cerr := strconv.Atoi(p); cerr == nil && v > 0 && v <= 65535 {
				port = v
			}
		}
		host = strings.TrimSpace(host)
		if host == "" {
			continue
		}
		if name == "" {
			// Port variants must not collide in the name-keyed dedupe, but a
			// colon would read as a malformed hostname in the list - use a
			// label-style suffix instead: "linuxdb (3131)".
			name = host
			if port != 22 {
				name = fmt.Sprintf("%s (%d)", host, port)
			}
		}
		if _, err := a.store.PutNamed(sessionstore.Profile{Name: name, Host: host, Port: port, Auth: sessionstore.AuthPassword}); err != nil {
			a.log("import skipped %q: %v", line, err)
			continue
		}
		count++
	}
	a.log("imported %d host(s) from pasted text", count)
	return count
}

// parseImportLine splits an import line into an optional label and the host
// part. Only explicit separators count; a lone token is just a host.
func parseImportLine(line string) (name, hostport string) {
	for _, sep := range []string{",", "="} {
		if i := strings.Index(line, sep); i >= 0 {
			return strings.TrimSpace(line[:i]), strings.TrimSpace(line[i+1:])
		}
	}
	if fields := strings.Fields(line); len(fields) == 2 {
		return fields[0], fields[1]
	}
	return "", line
}

// PickHostFile opens the file picker from the Import dialog and returns the
// chosen file's text (capped at 1 MiB) so it lands in the preview box before
// anything is saved. Returns "" when the dialog is cancelled.
func (a *App) PickHostFile() (string, error) {
	p, err := runtime.OpenFileDialog(a.ctx, runtime.OpenDialogOptions{
		Title: "Select hosts text file",
		Filters: []runtime.FileFilter{
			{DisplayName: "Text files (*.txt;*.list;*.csv;*.hosts)", Pattern: "*.txt;*.list;*.csv;*.hosts"},
			{DisplayName: "All files", Pattern: "*.*"},
		},
	})
	if err != nil || p == "" {
		return "", err
	}
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	const maxImportFile = 1 << 20
	buf := make([]byte, maxImportFile)
	n, _ := io.ReadFull(f, buf)
	a.log("host file picked: %s (%d bytes)", p, n)
	return string(buf[:n]), nil
}

// ReorderProfiles persists the display order of saved servers as the user
// arranged them by dragging rows in the list.
func (a *App) ReorderProfiles(ids []string) error {
	if a.store == nil {
		return fmt.Errorf("profile store unavailable")
	}
	a.log("profiles reordered (%d rows)", len(ids))
	return a.store.Reorder(ids)
}

// ---------- PTY I/O ----------

// WriteInput forwards raw keystrokes to the remote PTY.
func (a *App) WriteInput(sid, data string) error {
	ctrl, err := a.controllerFor(sid)
	if err != nil {
		return err
	}
	return ctrl.WriteInput([]byte(data))
}

// ResizeSession updates the PTY window size.
func (a *App) ResizeSession(sid string, cols, rows int) {
	a.mu.Lock()
	s, ok := a.sessions[sid]
	a.mu.Unlock()
	if ok {
		s.Ctrl.Resize(cols, rows)
	}
}

// ---------- SFTP file manager ----------

// FileEntry is the frontend view of an SFTP listing row.
type FileEntry struct {
	Name  string `json:"name"`
	Path  string `json:"path"`
	IsDir bool   `json:"isDir"`
	Size  int64  `json:"size"`
	Owner string `json:"owner"`
	Group string `json:"group"`
	Mode  string `json:"mode"`
	// Perm is the low nine permission bits as a three-digit octal (e.g. "644"),
	// the form the permission editor prefills and writes back.
	Perm  string `json:"perm"`
	MTime string `json:"mtime"`
}

// ListFiles returns the entries of a remote directory.
func (a *App) ListFiles(sid, p string) ([]FileEntry, error) {
	a.mu.Lock()
	s, ok := a.sessions[sid]
	var start string
	if ok {
		start = s.FilesPath
	}
	a.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("no session %s", sid)
	}
	if p == "" {
		p = start
	}
	sc, err := s.Ctrl.SFTP()
	if err != nil {
		return nil, err
	}
	entries, err := sc.List(p)
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	s.FilesPath = p
	a.mu.Unlock()
	out := make([]FileEntry, 0, len(entries))
	for _, e := range entries {
		out = append(out, FileEntry{
			Name: e.Name, Path: e.Path, IsDir: e.IsDir, Size: e.Size,
			Owner: e.Owner, Group: e.Group,
			Mode: e.Mode.String(), Perm: fmt.Sprintf("%03o", e.Mode.Perm()),
			MTime: e.ModTime.Format("2006-01-02 15:04"),
		})
	}
	return out, nil
}

// FollowCwd inspects one submitted shell command line and, when it confidently
// changes the remote working directory, points the session's file browser at
// the new place. It returns that path, or "" when the browser should stay put:
// the line was not a cd, its target cannot be named with certainty, or the
// directory does not exist / cannot be read (a failed cd must not blank out a
// working listing).
func (a *App) FollowCwd(sid, line string) string {
	a.mu.Lock()
	s, ok := a.sessions[sid]
	var cwd string
	if ok {
		cwd = s.FilesPath
	}
	a.mu.Unlock()
	if !ok {
		return ""
	}
	sc, err := s.Ctrl.SFTP()
	if err != nil {
		return ""
	}
	next, resolved := follow.Resolve(cwd, sc.Home(), line)
	if !resolved {
		// Never log the typed command line: shell history in a plaintext log
		// file is a security leak (paths may hold secrets, tokens, hostnames).
		// A miss is also the common case - every Enter arrives here.
		return ""
	}
	if fi, err := sc.Stat(next); err != nil || !fi.IsDir {
		// The failure path is not shown in the browser either, so it stays out
		// of the log as well; the error text can embed the attempted path.
		a.log("follow: cd target is not a usable directory (session %s)", sid)
		return ""
	}
	a.mu.Lock()
	s.FilesPath = next
	a.mu.Unlock()
	a.log("follow cd %s -> %s", sid, next)
	return next
}

// Mkdir creates a directory inside dir. The name is checked as a plain
// basename, so a typed "/" cannot place the new folder somewhere else.
func (a *App) Mkdir(sid, dir, name string) error {
	sc, err := a.sftpFor(sid)
	if err != nil {
		return err
	}
	name, err = remoteBase(name)
	if err != nil {
		return err
	}
	return sc.Mkdir(joinRemote(dir, name))
}

// NewFile creates an empty file inside dir. An existing name is reported as an
// error rather than overwritten.
func (a *App) NewFile(sid, dir, name string) error {
	sc, err := a.sftpFor(sid)
	if err != nil {
		return err
	}
	name, err = remoteBase(name)
	if err != nil {
		return err
	}
	return sc.Touch(joinRemote(dir, name))
}

// Delete removes a file or directory (recursively).
func (a *App) Delete(sid, p string) error {
	sc, err := a.sftpFor(sid)
	if err != nil {
		return err
	}
	return sc.Remove(p)
}

// Rename replaces the basename of p with name. Only a plain basename is accepted:
// a name carrying a separator would move the file out of the folder on screen,
// which reads as a failed rename rather than as the move it was.
func (a *App) Rename(sid, p, name string) error {
	sc, err := a.sftpFor(sid)
	if err != nil {
		return err
	}
	name, err = remoteBase(name)
	if err != nil {
		return err
	}
	return sc.Rename(p, joinRemote(path.Dir(p), name))
}

// ---------- permissions (chmod / chown) ----------

// parsePermOctal reads a chmod value written as one to four octal digits
// ("644", "0644", "0755"). Only the low nine bits are kept: the special
// setuid/setgid/sticky bits are deliberately out of scope for the checkbox
// editor, and masking them off is safer than guessing at a four-digit entry the
// user did not mean to type.
func parsePermOctal(s string) (os.FileMode, error) {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 4 {
		return 0, fmt.Errorf("permissions must be 1-4 octal digits (e.g. 644)")
	}
	v, err := strconv.ParseUint(s, 8, 32)
	if err != nil {
		return 0, fmt.Errorf("permissions must be octal (0-7): %q", s)
	}
	return os.FileMode(v) & 0o777, nil
}

// resolveID turns one chown field into a numeric id: empty means "leave it
// unchanged" (-1), an all-digit field is taken as the id itself, and anything
// else is looked up through the given resolver. A name that resolves nowhere is
// an error rather than a silent no-op, so a typo never looks like a successful
// ownership change.
func resolveID(field string, lookup func(string) (int, bool), what string) (int, error) {
	field = strings.TrimSpace(field)
	if field == "" {
		return -1, nil
	}
	if n, err := strconv.Atoi(field); err == nil && n >= 0 {
		return n, nil
	}
	if id, ok := lookup(field); ok {
		return id, nil
	}
	return 0, fmt.Errorf("unknown %s %q", what, field)
}

// SetPermissions chmods a remote path to the given octal mode.
func (a *App) SetPermissions(sid, p, octal string) error {
	sc, err := a.sftpFor(sid)
	if err != nil {
		return err
	}
	mode, err := parsePermOctal(octal)
	if err != nil {
		return err
	}
	if err := sc.Chmod(p, mode); err != nil {
		return err
	}
	a.log("chmod %s -> %04o", p, mode)
	return nil
}

// SetOwner chowns a remote path. An empty owner or group leaves that field
// untouched; a name is resolved through the server's account files.
func (a *App) SetOwner(sid, p, owner, group string) error {
	sc, err := a.sftpFor(sid)
	if err != nil {
		return err
	}
	uid, err := resolveID(owner, sc.LookupUser, "user")
	if err != nil {
		return err
	}
	gid, err := resolveID(group, sc.LookupGroup, "group")
	if err != nil {
		return err
	}
	if uid < 0 && gid < 0 {
		return fmt.Errorf("nothing to change")
	}
	if err := sc.Chown(p, uid, gid); err != nil {
		return err
	}
	a.log("chown %s -> %s:%s", p, owner, group)
	return nil
}

// ---------- in-app file editor ----------

// maxEditFileBytes caps what the editor will load. Anything larger is almost
// certainly a log, an image or an archive, and pulling it across SFTP into a
// text box would hang the pane for no benefit.
const maxEditFileBytes = 1 << 20 // 1 MiB

// FileContent is the editor's read payload. Binary flags a file whose bytes are
// not text, so the UI can open it read-only instead of mangling it; Size is the
// byte length actually loaded.
type FileContent struct {
	Path    string `json:"path"`
	Content string `json:"content"`
	Size    int64  `json:"size"`
	Binary  bool   `json:"binary"`
}

// looksBinary reports whether the leading bytes look non-text: a NUL byte in
// the first chunk is the classic signal, and it is cheap enough to run on every
// open. UTF-8 and Latin-1 text never contain a raw NUL.
func looksBinary(data []byte) bool {
	probe := data
	if len(probe) > 8000 {
		probe = probe[:8000]
	}
	return bytes.IndexByte(probe, 0) >= 0
}

// ReadRemoteFile loads a file's contents for the editor. A file over the size
// cap or a directory is refused with an error the UI shows directly.
func (a *App) ReadRemoteFile(sid, p string) (FileContent, error) {
	sc, err := a.sftpFor(sid)
	if err != nil {
		return FileContent{}, err
	}
	data, err := sc.ReadFile(p, maxEditFileBytes)
	if err != nil {
		return FileContent{}, err
	}
	return FileContent{Path: p, Content: string(data), Size: int64(len(data)), Binary: looksBinary(data)}, nil
}

// WriteRemoteFile saves the editor's text back over the remote file. It is a
// whole-file replace, so an empty string legitimately empties the file.
func (a *App) WriteRemoteFile(sid, p, content string) error {
	sc, err := a.sftpFor(sid)
	if err != nil {
		return err
	}
	if err := sc.WriteFile(p, []byte(content)); err != nil {
		return err
	}
	a.log("saved %s (%d bytes)", p, len(content))
	return nil
}

// ---------- transfer queue ----------

// QueueItem is the frontend view of a transfer with progress/speed/ETA.
type QueueItem struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Direction   string `json:"direction"`
	Status      string `json:"status"`
	Progress    int    `json:"progress"`
	Speed       string `json:"speed"`
	ETA         string `json:"eta"`
	Transferred string `json:"transferred"`
	Total       string `json:"total"`
	Error       string `json:"error"`
	// Batch groups the rows one action queued, and BatchLabel names that group for
	// the summary line the queue shows once every row in it has settled. Both are 0
	// and "" for a single file queued on its own.
	Batch      int    `json:"batch"`
	BatchLabel string `json:"batchLabel"`
}

// queueSnapshot is the "queue:progress" event payload: the same rows QueueList
// answers with, pushed on the queue's own cadence instead of pulled by the UI.
type queueSnapshot struct {
	SID   string      `json:"sid"`
	Items []QueueItem `json:"items"`
}

// emitQueueProgress builds the callback the transfer queue rings. It runs on
// the pump goroutine through a bound session id, so it re-reads the live queue
// rather than capturing one: a queue is replaced if its session reconnects.
func (a *App) emitQueueProgress(sid string) func() {
	return func() {
		q := a.queueOf(sid)
		if q == nil {
			return
		}
		snap := queueSnapshot{SID: sid, Items: make([]QueueItem, 0, len(q.GetItems()))}
		for _, it := range q.GetItems() {
			st, _ := time.Parse(time.RFC3339, it.StartTime)
			dir := "download"
			if it.Direction == transfer.Upload {
				dir = "upload"
			}
			snap.Items = append(snap.Items, QueueItem{
				ID: it.ID, Name: it.FileName, Direction: dir, Status: it.Status.String(),
				Progress: it.Progress(), Speed: transfer.FormatSpeed(it.Speed(st)), ETA: it.ETA(st),
				Transferred: transfer.FormatSize(it.TransferBytes), Total: transfer.FormatSize(it.TotalBytes), Error: it.ErrorMsg,
			})
		}
		runtime.EventsEmit(a.ctx, "queue:progress", snap)
	}
}

// PickSSHKey opens a native file dialog so the user can choose a private key
// instead of typing its path. It returns "" when the dialog is cancelled. The
// "All files" filter is first so extension-less keys (id_rsa) are visible.
func (a *App) PickSSHKey() (string, error) {
	return runtime.OpenFileDialog(a.ctx, runtime.OpenDialogOptions{
		Title: "Select SSH private key",
		Filters: []runtime.FileFilter{
			{DisplayName: "All files", Pattern: "*.*"},
			{DisplayName: "SSH keys (*.pem;*.ppk;id_*)", Pattern: "*.pem;*.ppk;id_*"},
		},
	})
}

// Upload picks a local file and enqueues an upload to remoteDir. policy is the
// transfer-conflict rule (overwrite/rename/skip) applied when the remote path
// already exists.
func (a *App) Upload(sid, remoteDir, policy string) error {
	local, err := runtime.OpenFileDialog(a.ctx, runtime.OpenDialogOptions{Title: "Select file to upload"})
	if err != nil || local == "" {
		return err
	}
	q, err := a.queueFor(sid)
	if err != nil {
		return err
	}
	sc, err := a.sftpFor(sid)
	if err != nil {
		return err
	}
	remote := joinRemote(remoteDir, filepath.Base(local))
	dest, ok := remoteDestDecision(sc, remote, transfer.ParsePolicy(policy))
	if !ok {
		a.log("upload skipped (exists): %s", remote)
		return nil
	}
	q.AddUpload(local, dest)
	a.log("upload queued: %s -> %s", local, dest)
	return nil
}

// Download prompts for a local path and enqueues a download of remotePath.
// policy decides what happens when the chosen local file already exists.
func (a *App) Download(sid, remotePath, policy string) error {
	dest, err := runtime.SaveFileDialog(a.ctx, runtime.SaveDialogOptions{Title: "Save file as", DefaultFilename: path.Base(remotePath)})
	if err != nil || dest == "" {
		return err
	}
	q, err := a.queueFor(sid)
	if err != nil {
		return err
	}
	dest, ok := transfer.LocalDestDecision(dest, transfer.ParsePolicy(policy))
	if !ok {
		a.log("download skipped (exists): %s", dest)
		return nil
	}
	q.AddDownload(remotePath, dest)
	a.log("download queued: %s -> %s", remotePath, dest)
	return nil
}

// DownloadDir prompts for a local folder and enqueues every file under
// remotePath, mirroring the remote tree inside a subfolder named after it.
// policy is applied to each mirrored local destination.
func (a *App) DownloadDir(sid, remotePath, policy string) error {
	destRoot, err := runtime.OpenDirectoryDialog(a.ctx, runtime.OpenDialogOptions{Title: "Save folder to"})
	if err != nil || destRoot == "" {
		return err
	}
	base := strings.TrimRight(remotePath, "/")
	if base == "" {
		return fmt.Errorf("downloading the filesystem root is not supported")
	}
	sc, err := a.sftpFor(sid)
	if err != nil {
		return err
	}
	paths, dirs, err := sc.WalkTree(base, maxDownloadFiles)
	if err != nil {
		return err
	}
	q, err := a.queueFor(sid)
	if err != nil {
		return err
	}
	pol := transfer.ParsePolicy(policy)
	// One batch for the whole folder: the rows it queues are reported back as a
	// single "N copied, N skipped, N failed" line when the last of them settles.
	q.BeginBatch("Download folder " + path.Base(base))
	defer q.EndBatch()
	mirrorRoot := filepath.Join(destRoot, path.Base(base))
	// Create every remote directory locally before enqueuing any file, so
	// empty subdirectories are mirrored even when no file lands inside them.
	for _, relDir := range dirs {
		if err := os.MkdirAll(filepath.Join(mirrorRoot, filepath.FromSlash(relDir)), 0o755); err != nil {
			return err
		}
	}
	queued := 0
	var skips []skipEntry
	for _, p := range paths {
		rel := strings.TrimPrefix(p, base+"/")
		dest := filepath.Join(mirrorRoot, filepath.FromSlash(rel))
		var ok bool
		if dest, ok = transfer.LocalDestDecision(dest, pol); !ok {
			skips = append(skips, skipEntry{path: p, reason: "already there (skip policy)"})
			continue
		}
		q.AddDownload(p, dest)
		queued++
	}
	addSkipRows(q, transfer.Download, skips)
	a.log("download folder queued: %s (%d/%d files, %d dirs, %d skipped) -> %s", base, queued, len(paths), len(dirs), len(skips), destRoot)
	return nil
}

// UploadDir picks a local folder and enqueues every file inside it through
// queueLocalTree, which is the same path a dropped folder takes - so a folder
// behaves identically however it was chosen, and the conflict policy, the file
// cap and the skip rows all come from one place.
func (a *App) UploadDir(sid, remoteDir, policy string) error {
	root, err := runtime.OpenDirectoryDialog(a.ctx, runtime.OpenDialogOptions{Title: "Select folder to upload"})
	if err != nil || root == "" {
		return err
	}
	q, err := a.queueFor(sid)
	if err != nil {
		return err
	}
	sc, err := a.sftpFor(sid)
	if err != nil {
		return err
	}
	q.BeginBatch("Upload folder " + filepath.Base(root))
	defer q.EndBatch()
	queued, skips, err := queueLocalTree(q, sc, transfer.ParsePolicy(policy), root, remoteDir)
	addSkipRows(q, transfer.Upload, skips)
	if err != nil {
		return err
	}
	a.log("upload folder queued: %s (%d files, %d skipped) -> %s", root, queued, len(skips), strings.TrimRight(remoteDir, "/")+"/"+filepath.Base(root))
	return nil
}

// UploadPaths queues the local paths the user dropped onto the file pane. A file
// goes into remoteDir under its own name; a folder is mirrored exactly as the
// picker mirrors it. Each path is judged on its own, so one unreadable entry in a
// mixed drop cannot swallow the rest, and the refusal is logged per path.
func (a *App) UploadPaths(sid, remoteDir, policy string, paths []string) error {
	if len(paths) == 0 {
		return fmt.Errorf("nothing was dropped")
	}
	q, err := a.queueFor(sid)
	if err != nil {
		return err
	}
	sc, err := a.sftpFor(sid)
	if err != nil {
		return err
	}
	pol := transfer.ParsePolicy(policy)
	q.BeginBatch(fmt.Sprintf("Drop %d item(s)", len(paths)))
	defer q.EndBatch()
	queued, refused, skipped := 0, 0, 0
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		// Only a real local path can be uploaded. A webview can be handed anything
		// a page put on the clipboard, so this is checked rather than trusted.
		if !filepath.IsAbs(p) {
			refused++
			a.log("upload refused: %s is not an absolute local path", p)
			continue
		}
		fi, serr := os.Stat(p)
		if serr != nil {
			refused++
			a.log("upload refused: %s: %v", p, serr)
			continue
		}
		if fi.IsDir() {
			n, skips, terr := queueLocalTree(q, sc, pol, p, remoteDir)
			addSkipRows(q, transfer.Upload, skips)
			skipped += len(skips)
			if terr != nil {
				refused++
				a.log("upload refused: %s: %v", p, terr)
				continue
			}
			queued += n
			continue
		}
		dest, ok := remoteDestDecision(sc, joinRemote(remoteDir, filepath.Base(p)), pol)
		if !ok {
			skipped++
			q.AddSkipped(transfer.Upload, p, dest, "already there (skip policy)")
			continue
		}
		q.AddUpload(p, dest)
		queued++
	}
	a.log("drop queued: %d file(s), %d skipped, %d refused -> %s", queued, skipped, refused, remoteDir)
	if queued == 0 {
		if refused > 0 {
			return fmt.Errorf("nothing in the drop could be uploaded")
		}
		return fmt.Errorf("nothing to upload")
	}
	return nil
}

// skipEntry is a path a folder walk left out, with the reason its queue row will
// carry. Links are the common case; an unreadable directory is the other.
type skipEntry struct {
	path   string
	reason string
}

// skipRowLimit bounds how many skip rows one folder copy may add. A tree of
// nothing but links should still say so, but not by pushing ten thousand rows into
// a list the UI polls every 600ms - past the limit the rest collapse into one row.
const skipRowLimit = 200

// addSkipRows turns what the walk left out into settled queue rows, so the counts
// in the batch summary match what the user pointed at instead of losing files
// between the disk and the screen.
func addSkipRows(q *transfer.TransferQueue, d transfer.TransferDirection, skips []skipEntry) {
	if len(skips) == 0 {
		return
	}
	shown := skips
	if len(shown) > skipRowLimit {
		shown = shown[:skipRowLimit]
	}
	for _, s := range shown {
		if d == transfer.Upload {
			q.AddSkipped(d, s.path, "", s.reason)
		} else {
			q.AddSkipped(d, "", s.path, s.reason)
		}
	}
	if extra := len(skips) - len(shown); extra > 0 {
		q.AddSkipped(d, "", "", fmt.Sprintf("and %d more", extra))
	}
}

// queueLocalTree mirrors the local folder root into remoteDir: it walks the disk,
// creates the remote shape with MkdirAll first (so a deep tree queues cleanly even
// when no intermediate directory exists yet, and empty folders survive), then
// queues every file through the conflict policy. It answers how many files were
// queued and which paths were left out, with the reason - the caller turns those
// into rows.
//
// The same cap as the download side applies: pointing it at something like
// C:\Windows must answer with a message instead of queueing tens of thousands of
// transfers.
func queueLocalTree(q *transfer.TransferQueue, sc *sftpclient.Client, pol transfer.ConflictPolicy, root, remoteDir string) (int, []skipEntry, error) {
	var files []string
	// subDirs collects every local directory visited during WalkDir, except
	// the root itself and symlinks. Empty ones are the whole point: without
	// this list a tree of folders that contains no files would upload as
	// nothing.
	var subDirs []string
	var skips []skipEntry
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if d != nil && d.IsDir() {
				skips = append(skips, skipEntry{path: p, reason: "unreadable folder"})
				return filepath.SkipDir
			}
			skips = append(skips, skipEntry{path: p, reason: "unreadable"})
			return nil
		}
		if d.IsDir() {
			// Skip symlinks-to-directories (same rule as files below).
			if d.Type()&os.ModeSymlink != 0 {
				skips = append(skips, skipEntry{path: p, reason: "symbolic link"})
				return filepath.SkipDir
			}
			if p != root {
				subDirs = append(subDirs, p)
			}
			return nil
		}
		// A symlinked file would be uploaded with its link's size but the
		// target's contents; walking through symlinked directories is the
		// same recipe for loops. Only the real tree is mirrored.
		if d.Type()&os.ModeSymlink != 0 {
			skips = append(skips, skipEntry{path: p, reason: "symbolic link"})
			return nil
		}
		if len(files) >= maxDownloadFiles {
			return fmt.Errorf("folder has more than %d files; pick a smaller one", maxDownloadFiles)
		}
		files = append(files, p)
		return nil
	})
	if err != nil {
		return 0, skips, err
	}
	if len(files) == 0 && len(subDirs) == 0 {
		if len(skips) > 0 {
			// Everything in the pick was links or unreadable: saying "no
			// files" after opening a folder the user can see is a gaslight.
			return 0, skips, fmt.Errorf("%s holds only links or unreadable entries", root)
		}
		return 0, skips, fmt.Errorf("no files under %s", root)
	}

	base := strings.TrimRight(remoteDir, "/") + "/" + filepath.Base(root)
	// Each file's remote directory AND every visited local subdirectory maps to
	// a remote path, deepest first. MkdirAll answers nil for an existing
	// directory, so repeats are cheap and need no pre-check. Empty directories
	// are intentionally included: without them a folder with only sub-folders
	// would upload as a zero-byte file list.
	dirs := make(map[string]bool, len(files)+len(subDirs))
	for _, p := range files {
		rel, rerr := filepath.Rel(root, filepath.Dir(p))
		if rerr != nil {
			return 0, skips, rerr
		}
		dirs[strings.TrimRight(path.Join(base, filepath.ToSlash(rel)), "/")] = true
	}
	for _, p := range subDirs {
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil {
			return 0, skips, rerr
		}
		dirs[strings.TrimRight(path.Join(base, filepath.ToSlash(rel)), "/")] = true
	}
	for d := range dirs {
		if err := sc.MkdirAll(d); err != nil {
			return 0, skips, err
		}
	}
	queued := 0
	for _, p := range files {
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil {
			return queued, skips, rerr
		}
		dest, ok := remoteDestDecision(sc, path.Join(base, filepath.ToSlash(rel)), pol)
		if !ok {
			skips = append(skips, skipEntry{path: p, reason: "already there (skip policy)"})
			continue
		}
		q.AddUpload(p, dest)
		queued++
	}
	return queued, skips, nil
}

// remoteDestDecision applies a conflict policy to a remote destination path,
// the SFTP mirror of transfer.LocalDestDecision: Skip drops the row when the
// path exists, Rename picks a free "name (n).ext", Overwrite returns it as-is.
func remoteDestDecision(sc *sftpclient.Client, dest string, policy transfer.ConflictPolicy) (string, bool) {
	switch policy {
	case transfer.Skip:
		if transfer.RemoteExists(sc.Raw(), dest) {
			return dest, false
		}
	case transfer.Rename:
		return transfer.UniqueRemotePath(dest, func(p string) bool { return transfer.RemoteExists(sc.Raw(), p) }), true
	}
	return dest, true
}

// queueOf returns the transfer queue a session already has, or nil. Wails runs
// every bound method on its own goroutine, so the queue must be read under
// a.mu: the 600ms poll would otherwise race the click that installs the queue.
func (a *App) queueOf(sid string) *transfer.TransferQueue {
	a.mu.Lock()
	defer a.mu.Unlock()
	if s, ok := a.sessions[sid]; ok {
		return s.queue
	}
	return nil
}

// QueueList returns the transfer queue for a session with computed metrics.
func (a *App) QueueList(sid string) ([]QueueItem, error) {
	q := a.queueOf(sid)
	if q == nil {
		return []QueueItem{}, nil
	}
	out := []QueueItem{}
	for _, it := range q.GetItems() {
		st, _ := time.Parse(time.RFC3339, it.StartTime)
		dir := "download"
		if it.Direction == transfer.Upload {
			dir = "upload"
		}
		out = append(out, QueueItem{
			ID: it.ID, Name: it.FileName, Direction: dir, Status: it.Status.String(),
			Progress: it.Progress(), Speed: transfer.FormatSpeed(it.Speed(st)), ETA: it.ETA(st),
			Transferred: transfer.FormatSize(it.TransferBytes), Total: transfer.FormatSize(it.TotalBytes), Error: it.ErrorMsg,
			Batch: it.Batch, BatchLabel: q.BatchLabel(it.Batch),
		})
	}
	return out, nil
}

// QueueCancel cancels a queued/in-progress transfer.
func (a *App) QueueCancel(sid string, id int) error {
	q := a.queueOf(sid)
	if q == nil {
		return fmt.Errorf("no session")
	}
	q.CancelItem(id)
	return nil
}

// QueuePause holds back a queued transfer, or stops a running one at the next
// chunk. The bytes already moved are kept, so QueueResume continues from that
// offset instead of restarting the file.
func (a *App) QueuePause(sid string, id int) error {
	q := a.queueOf(sid)
	if q == nil {
		return fmt.Errorf("no session")
	}
	q.PauseItem(id)
	return nil
}

// QueueResume re-queues a paused transfer from where it stopped.
func (a *App) QueueResume(sid string, id int) error {
	q := a.queueOf(sid)
	if q == nil {
		return fmt.Errorf("no session")
	}
	q.ResumeItem(id)
	return nil
}

// QueueClear removes completed/failed/cancelled items from the queue.
func (a *App) QueueClear(sid string) error {
	q := a.queueOf(sid)
	if q == nil {
		return nil
	}
	q.ClearCompleted()
	return nil
}

// queueFor lazily builds a transfer queue bound to the session's SFTP client.
func (a *App) queueFor(sid string) (*transfer.TransferQueue, error) {
	a.mu.Lock()
	s, ok := a.sessions[sid]
	var q *transfer.TransferQueue
	if ok {
		q = s.queue
	}
	a.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("no session %s", sid)
	}
	if q != nil {
		return q, nil
	}
	// Opening SFTP is a network round trip, so it must happen with a.mu released:
	// holding it across the handshake stalls every other bound call - the 5s
	// session poll, the queue poll, terminal I/O - behind a slow or dead server.
	sc, err := s.Ctrl.SFTP()
	if err != nil {
		return nil, err
	}
	built := transfer.NewTransferQueue(sc.Raw(), maxConcurrentTransfers)
	// The transfer pump rings this after each copyChunkSize chunk; the queue throttles
	// the rings to a UI cadence, so the frontend never has to poll while bytes
	// are actually moving.
	built.SetOnProgress(a.emitQueueProgress(sid))
	a.mu.Lock()
	if s.queue == nil {
		s.queue = built
	}
	// Another caller may have finished its handshake first; sharing that queue
	// keeps one progress list per session. Ours started nothing, so dropping it
	// releases no resources.
	q = s.queue
	a.mu.Unlock()
	return q, nil
}

// ---------- tunnels ----------

// TunnelInfo describes an active forward tunnel of either kind.
type TunnelInfo struct {
	ID         string `json:"id"`
	SessionID  string `json:"sessionId"`
	Name       string `json:"name"`
	Type       string `json:"type"`
	Kind       string `json:"kind"`
	Bind       string `json:"bind"`
	LocalPort  int    `json:"localPort"`
	RemoteHost string `json:"remoteHost"`
	RemotePort int    `json:"remotePort"`
	Remote     string `json:"remote"`
	Running    bool   `json:"running"`
	// Orphaned is true when the backing session is gone but the definition is
	// kept in a.tunnels so the user sees the row in the table. It can be
	// re-started automatically when a new session to ProfileAddr opens.
	Orphaned bool `json:"orphaned"`
	// ProfileAddr is the "host:port" SSH server that owns this definition;
	// it explains to the UI why an orphaned row exists.
	ProfileAddr string `json:"profileAddr"`
}

// tunnelInfo projects a tunnel onto its UI row.
func tunnelInfo(t *tunnel) TunnelInfo {
	bind := "local"
	if t.bindAll {
		bind = "lan"
	}
	return TunnelInfo{
		ID: t.ID, SessionID: t.SessionID, Name: t.Name,
		Type: t.typeName(), Kind: t.kind(), Bind: bind,
		LocalPort: t.LocalPort, RemoteHost: t.RemoteHost, RemotePort: t.RemotePort,
		Remote: t.remoteAddr(), Running: t.running(),
		Orphaned:    t.SessionID == "",
		ProfileAddr: t.profileAddr,
	}
}

// bindIsLAN maps the frontend's "lan"/"local" bind value onto the flag.
func bindIsLAN(bind string) bool { return bind == "lan" }

// OpenTunnel starts a local port forward through the session's SSH connection.
// name labels the row; a blank name falls back to "local -> destination".
// bind is "local" (127.0.0.1, the default) or "lan" (0.0.0.0, reachable from
// other devices on the network).
func (a *App) OpenTunnel(sid, name string, localPort int, remoteHost string, remotePort int, bind string) (*TunnelInfo, error) {
	ctrl, err := a.controllerFor(sid)
	if err != nil {
		return nil, err
	}
	client := ctrl.SSHClient()
	if client == nil {
		return nil, fmt.Errorf("not connected")
	}
	if err := validPort("local", localPort); err != nil {
		return nil, err
	}
	if err := validPort("remote", remotePort); err != nil {
		return nil, err
	}
	// The destination is checked in the same breath as the ports: a forward whose
	// target can never be dialled is not opened at all, because it would sit in the
	// table reading "running" until the first connection proved otherwise.
	if err := validForwardHost(remoteHost); err != nil {
		return nil, err
	}
	t := &tunnel{ID: sessionstore.NewID(), SessionID: sid, LocalPort: localPort, RemoteHost: strings.TrimSpace(remoteHost), RemotePort: remotePort, bindAll: bindIsLAN(bind), Name: strings.TrimSpace(name), profileAddr: a.profileAddrFor(sid), autoStart: true}
	if t.Name == "" {
		t.Name = fmt.Sprintf("%d \u2192 %s", localPort, t.remoteAddr())
	}
	ln, err := net.Listen("tcp", t.localAddr())
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", t.localAddr(), err)
	}
	t.listener = ln
	a.mu.Lock()
	a.tunnels[t.ID] = t
	a.mu.Unlock()
	a.persistTunnel(t)
	go a.serveTunnel(client, ln, t.remoteAddr())
	a.log("tunnel %s (%s) -> %s", t.localAddr(), t.Name, t.remoteAddr())
	info := tunnelInfo(t)
	return &info, nil
}

// OpenDynamicTunnel starts a SOCKS5 dynamic (-D) forward: the local port
// speaks SOCKS and every client request picks its own destination, dialled
// through the session's SSH connection. Like PuTTY's "Dynamic" it needs no
// remote host or port up front. bind is "local" or "lan" - a LAN bind turns
// the port into a proxy other devices (a phone, another PC) can use.
func (a *App) OpenDynamicTunnel(sid, name string, localPort int, bind string) (*TunnelInfo, error) {
	ctrl, err := a.controllerFor(sid)
	if err != nil {
		return nil, err
	}
	client := ctrl.SSHClient()
	if client == nil {
		return nil, fmt.Errorf("not connected")
	}
	if err := validPort("local", localPort); err != nil {
		return nil, err
	}
	t := &tunnel{ID: sessionstore.NewID(), SessionID: sid, LocalPort: localPort, dynamic: true, bindAll: bindIsLAN(bind), Name: strings.TrimSpace(name), profileAddr: a.profileAddrFor(sid), autoStart: true}
	if t.Name == "" {
		t.Name = fmt.Sprintf("SOCKS on %d", localPort)
	}
	ln, err := net.Listen("tcp", t.localAddr())
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", t.localAddr(), err)
	}
	t.listener = ln
	a.mu.Lock()
	a.tunnels[t.ID] = t
	a.mu.Unlock()
	a.persistTunnel(t)
	go a.serveDynamic(client, ln)
	a.log("tunnel %s (%s) -> SOCKS dynamic", t.localAddr(), t.Name)
	info := tunnelInfo(t)
	return &info, nil
}

// OpenRemoteTunnel starts a reverse (-R) forward: it asks the SSH server to
// listen on remoteHost:remotePort, and every connection the server accepts on
// that port is carried back through the tunnel to a service on this machine at
// 127.0.0.1:localPort. remoteHost may be empty, which lets the server bind its
// own default (loopback); bind is then the choice PuTTY spells as "remote ports
// do the same": "local" keeps that default, "lan" asks for every interface -
// which sshd grants only with GatewayPorts. Unlike a local forward there is no
// listener on this side to bind, so bind says nothing about this machine.
func (a *App) OpenRemoteTunnel(sid, name string, remoteHost string, remotePort, localPort int, bind string) (*TunnelInfo, error) {
	ctrl, err := a.controllerFor(sid)
	if err != nil {
		return nil, err
	}
	client := ctrl.SSHClient()
	if client == nil {
		return nil, fmt.Errorf("not connected")
	}
	if err := validPort("local", localPort); err != nil {
		return nil, err
	}
	if err := validPort("remote", remotePort); err != nil {
		return nil, err
	}
	// An empty bind host is PuTTY's behaviour: the server chooses. Anything typed
	// still has to be a valid address, because sshd rejects the whole request
	// otherwise and the row would appear never to have been created at all.
	if h := strings.TrimSpace(remoteHost); h != "" {
		if err := validForwardHost(h); err != nil {
			return nil, err
		}
	}
	t := &tunnel{ID: sessionstore.NewID(), SessionID: sid, LocalPort: localPort, RemoteHost: strings.TrimSpace(remoteHost), RemotePort: remotePort, bindAll: bindIsLAN(bind), remote: true, Name: strings.TrimSpace(name), profileAddr: a.profileAddrFor(sid), autoStart: true}
	if t.Name == "" {
		t.Name = fmt.Sprintf("%s \u2192 localhost:%d", t.remoteAddr(), localPort)
	}
	// Ask the server to open the port. A refusal (a non-loopback bind without
	// GatewayPorts, or the port already taken on the server) surfaces here
	// rather than at first connection.
	rl, err := client.Listen("tcp", t.serverBindAddr())
	if err != nil {
		return nil, fmt.Errorf("remote listen %s: %w", t.remoteAddr(), err)
	}
	t.listener = rl
	a.mu.Lock()
	a.tunnels[t.ID] = t
	a.mu.Unlock()
	a.persistTunnel(t)
	go a.serveRemote(rl, t.localTarget())
	a.log("tunnel %s (%s) reverse -> %s", t.remoteAddr(), t.Name, t.localTarget())
	info := tunnelInfo(t)
	return &info, nil
}

// StopTunnel closes the listener but keeps the definition, so the row stays in
// the table and can be started again with the same parameters.
func (a *App) StopTunnel(id string) error {
	a.mu.Lock()
	t, ok := a.tunnels[id]
	var ln net.Listener
	if ok {
		ln = t.listener
		t.listener = nil
	}
	a.mu.Unlock()
	if !ok {
		return fmt.Errorf("no such tunnel")
	}
	if ln != nil {
		if err := ln.Close(); err != nil {
			a.log("stop tunnel %s: %v", id, err)
		}
	}
	a.log("tunnel stopped %s", id)
	return nil
}

// StartTunnel binds a listener for a stopped definition and serves it. It is a
// no-op when the forward is already running.
func (a *App) StartTunnel(id string) error {
	a.mu.Lock()
	t, ok := a.tunnels[id]
	if !ok {
		a.mu.Unlock()
		return fmt.Errorf("no such tunnel")
	}
	if t.running() {
		a.mu.Unlock()
		return nil
	}
	sid, local, remote := t.SessionID, t.localAddr(), t.remoteAddr()
	isDynamic, isRemote := t.dynamic, t.remote
	serverBind, localTarget := t.serverBindAddr(), t.localTarget()
	host := t.RemoteHost
	a.mu.Unlock()

	// A definition with an unusable destination is not started, however it got
	// here - saved by an earlier build, or hand-edited into tunnels.json. The row
	// stays stopped and the log says why, instead of a listener opening onto a path
	// that cannot be dialled. A reverse forward may name no bind host at all.
	if !isDynamic && !(isRemote && strings.TrimSpace(host) == "") {
		if err := validForwardHost(host); err != nil {
			return err
		}
	}

	ctrl, err := a.controllerFor(sid)
	if err != nil {
		return err
	}
	client := ctrl.SSHClient()
	if client == nil {
		return fmt.Errorf("not connected")
	}
	// A reverse forward has nothing to bind locally: it asks the server to open
	// the port instead, so the listener is an ssh.Client listener rather than a
	// net one. Both satisfy net.Listener, so the shared bookkeeping below is the
	// same and closing it later sends the cancel-tcpip-forward.
	var ln net.Listener
	if isRemote {
		ln, err = client.Listen("tcp", serverBind)
	} else {
		ln, err = net.Listen("tcp", local)
	}
	if err != nil {
		if isRemote {
			return fmt.Errorf("remote listen %s: %w", remote, err)
		}
		return fmt.Errorf("listen %s: %w", local, err)
	}
	a.mu.Lock()
	if a.tunnels[id] != t {
		// The row was closed while we were binding. Hand the port straight back:
		// serving on a definition the UI no longer lists would leak a listener
		// that nothing can stop later.
		a.mu.Unlock()
		_ = ln.Close()
		return fmt.Errorf("no such tunnel")
	}
	if t.running() {
		// Another call won the race while we were binding.
		a.mu.Unlock()
		_ = ln.Close()
		return nil
	}
	t.listener = ln
	a.mu.Unlock()
	switch {
	case isDynamic:
		go a.serveDynamic(client, ln)
		a.log("tunnel started %s (SOCKS)", local)
	case isRemote:
		go a.serveRemote(ln, localTarget)
		a.log("tunnel started reverse %s -> %s", remote, localTarget)
	default:
		go a.serveTunnel(client, ln, remote)
		a.log("tunnel started %s -> %s", local, remote)
	}
	return nil
}

// UpdateTunnel replaces a tunnel's parameters in place, keeping its row. The
// forward is stopped, the new values applied and it is started again; if the new
// settings cannot be bound the definition survives with them and the row simply
// reads "stopped", so the fix is a click rather than a retyped tunnel.
func (a *App) UpdateTunnel(id, name string, localPort int, remoteHost string, remotePort int, bind string) (*TunnelInfo, error) {
	// Validate before anything is torn down: an edit with an out-of-range port
	// must not stop a forward that is currently carrying traffic and then fail.
	a.mu.Lock()
	t, ok := a.tunnels[id]
	a.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("no such tunnel")
	}
	if err := validPort("local", localPort); err != nil {
		return nil, err
	}
	if !t.dynamic {
		if err := validPort("remote", remotePort); err != nil {
			return nil, err
		}
		// The destination is validated before anything is torn down, so an edit that
		// types a port into the host box cannot stop a working forward and leave it
		// restarted as a broken one. A reverse forward may bind the server's default.
		if !(t.remote && strings.TrimSpace(remoteHost) == "") {
			if err := validForwardHost(remoteHost); err != nil {
				return nil, err
			}
		}
	}
	if err := a.StopTunnel(id); err != nil {
		return nil, err
	}
	a.mu.Lock()
	t, ok = a.tunnels[id]
	if !ok {
		a.mu.Unlock()
		return nil, fmt.Errorf("no such tunnel")
	}
	if n := strings.TrimSpace(name); n != "" {
		t.Name = n
	}
	t.LocalPort = localPort
	t.bindAll = bindIsLAN(bind)
	// A dynamic forward dials no fixed target, so the remote fields stay unused.
	if !t.dynamic {
		t.RemoteHost, t.RemotePort = strings.TrimSpace(remoteHost), remotePort
	}
	info := tunnelInfo(t)
	a.mu.Unlock()

	if err := a.StartTunnel(id); err != nil {
		a.log("update tunnel %s failed: %v", id, err)
		return nil, err
	}
	a.persistTunnel(t)
	a.mu.Lock()
	info = tunnelInfo(t)
	a.mu.Unlock()
	return &info, nil
}

// tunnelDialTimeout bounds the SSH-side dial of a forwarded connection. A -L or
// -D forward can be bound to the LAN, and a target that swallows packets instead
// of refusing them would otherwise leave a goroutine parked in the handshake for
// as long as the client keeps its socket open. A var so the tests do not have to
// wait out the real budget.
var tunnelDialTimeout = 15 * time.Second

// sshDialer is the part of *ssh.Client the forwarders use. Naming it lets the
// dial-timeout behaviour be tested against a stub that never answers.
type sshDialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

// dialBounded opens a connection to target through the SSH link and gives up
// after tunnelDialTimeout. Client.DialContext closes a connection that completes
// late, so a slow server cannot smuggle one past the deadline.
func dialBounded(d sshDialer, network, target string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), tunnelDialTimeout)
	defer cancel()
	return d.DialContext(ctx, network, target)
}

func (a *App) serveTunnel(dialer sshDialer, ln net.Listener, target string) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go a.forward(dialer, conn, target)
	}
}

// serveDynamic accepts SOCKS5 clients on a dynamic forward's listener; each
// connection performs its own handshake and target dial over the SSH link.
func (a *App) serveDynamic(dialer sshDialer, ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			if err := socks.Serve(conn, func(network, addr string) (net.Conn, error) {
				return dialBounded(dialer, network, addr)
			}); err != nil {
				// A client hanging up mid-handshake is normal; keep it out of
				// the log so only real relay problems would stand out.
				_ = err
			}
		}()
	}
}

func (a *App) forward(dialer sshDialer, conn net.Conn, target string) {
	defer conn.Close()
	remote, err := dialBounded(dialer, "tcp", target)
	if err != nil {
		return
	}
	defer remote.Close()
	go func() { _, _ = io.Copy(remote, conn); remote.Close() }()
	_, _ = io.Copy(conn, remote)
}

// serveRemote accepts connections a reverse (-R) forward's server-side listener
// hands back through the tunnel. Each accepted net.Conn is one remote client's
// link, delivered here already wrapped by x/crypto, so -R is the mirror of
// serveTunnel with the two ends swapped.
func (a *App) serveRemote(rl net.Listener, target string) {
	for {
		conn, err := rl.Accept()
		if err != nil {
			return
		}
		go a.forwardLocal(conn, target)
	}
}

// forwardLocal connects a tunneled reverse-forward connection to the local
// service it was pointed at and pumps both directions until either side closes.
// The local dial is loopback but still bounded, so a target that is listening
// yet slow to accept cannot park a goroutine against the remote for good.
func (a *App) forwardLocal(remote net.Conn, target string) {
	defer remote.Close()
	d := &net.Dialer{Timeout: tunnelDialTimeout}
	local, err := d.Dial("tcp", target)
	if err != nil {
		return
	}
	defer local.Close()
	go func() { _, _ = io.Copy(local, remote); local.Close() }()
	_, _ = io.Copy(remote, local)
}

// CloseTunnel removes a tunnel definition entirely, including its stored
// row in tunnels.json. Use StopTunnel to keep the row for later use.
func (a *App) CloseTunnel(id string) error {
	a.mu.Lock()
	t, ok := a.tunnels[id]
	if ok {
		delete(a.tunnels, id)
	}
	a.mu.Unlock()
	if !ok {
		return fmt.Errorf("no such tunnel")
	}
	// Remove the persisted definition so it does not re-appear on the next
	// connection to the same server. Done after the lock release because the
	// store has its own mutex and we must not nest them.
	a.removeTunnelDef(t)
	return a.closeListenerOf(t)
}

// ListTunnels returns every tunnel definition, running or stopped.
func (a *App) ListTunnels() []TunnelInfo {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]TunnelInfo, 0, len(a.tunnels))
	for _, t := range a.tunnels {
		out = append(out, tunnelInfo(t))
	}
	return out
}

// ---------- helpers ----------

// profileAddrFor returns the "host:port" SSH address of the session's profile.
// It returns "" when the session is not found, causing persistTunnel and
// autoStartTunnels to skip that tunnel silently.
func (a *App) profileAddrFor(sid string) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if s, ok := a.sessions[sid]; ok {
		return s.Profile.Addr()
	}
	return ""
}

// persistTunnel writes t's parameters to tunnels.json. A nil store (startup
// error) or an empty profileAddr (test fixture, session gone before open) is
// silently ignored - without both there is nowhere to put the record.
//
// The definition is snapshotted under a.mu: UpdateTunnel rewrites those same
// fields while holding the lock, and autoStartTunnels walks the map for another
// session's Connect, so reading them unlocked would be a data race. The store
// call then runs outside a.mu because sessionstore owns a different mutex.
func (a *App) persistTunnel(t *tunnel) {
	if a.store == nil {
		return
	}
	a.mu.Lock()
	addr, def := t.profileAddr, sessionstore.TunnelDef{
		ID:          t.defID,
		ProfileAddr: t.profileAddr,
		Name:        t.Name,
		LocalPort:   t.LocalPort,
		RemoteHost:  t.RemoteHost,
		RemotePort:  t.RemotePort,
		Dynamic:     t.dynamic,
		Remote:      t.remote,
		BindAll:     t.bindAll,
		AutoStart:   t.autoStart,
	}
	a.mu.Unlock()
	if addr == "" {
		return
	}
	stored, err := a.store.PutTunnel(def)
	if err != nil {
		a.log("persist tunnel %s: %v", def.Name, err)
		return
	}
	// Capture the allocated ID so future updates reference the same row.
	a.mu.Lock()
	t.defID = stored.ID
	a.mu.Unlock()
}

// removeTunnelDef deletes t's persisted definition. Safe when defID is empty
// (the tunnel was never persisted) or the store is nil.
func (a *App) removeTunnelDef(t *tunnel) {
	if a.store == nil {
		return
	}
	a.mu.Lock()
	id, name := t.defID, t.Name
	a.mu.Unlock()
	if id == "" {
		return
	}
	if err := a.store.DeleteTunnelByDefID(id); err != nil {
		a.log("remove tunnel def %s (%s): %v", id, name, err)
	}
}

// autoStartTunnels restores stored definitions for profileAddr into live
// session sid. It first removes any orphaned in-memory rows that reference the
// same defs (a row whose session was closed), then creates a fresh live row for
// each def. Definitions marked AutoStart are started immediately; failures are
// logged so the row reads "stopped" rather than being silently dropped.
func (a *App) autoStartTunnels(profileAddr, sid string) {
	if a.store == nil || profileAddr == "" {
		return
	}
	defs := a.store.TunnelsForProfile(profileAddr)
	if len(defs) == 0 {
		return
	}
	// Drop orphaned rows that correspond to defs we are about to re-create so
	// the table shows one fresh row per stored definition.
	defIDs := make(map[string]bool, len(defs))
	for _, d := range defs {
		defIDs[d.ID] = true
	}
	a.mu.Lock()
	for id, t := range a.tunnels {
		if t.SessionID == "" && t.defID != "" && defIDs[t.defID] {
			delete(a.tunnels, id)
		}
	}
	a.mu.Unlock()
	for _, def := range defs {
		t := &tunnel{
			ID: sessionstore.NewID(), SessionID: sid,
			Name:        def.Name,
			LocalPort:   def.LocalPort,
			RemoteHost:  def.RemoteHost,
			RemotePort:  def.RemotePort,
			dynamic:     def.Dynamic,
			remote:      def.Remote,
			bindAll:     def.BindAll,
			profileAddr: profileAddr,
			defID:       def.ID,
			autoStart:   def.AutoStart,
		}
		a.mu.Lock()
		a.tunnels[t.ID] = t
		a.mu.Unlock()
		if def.AutoStart {
			if err := a.StartTunnel(t.ID); err != nil {
				a.log("auto-start %s: %v", t.Name, err)
			}
		}
	}
}

func (a *App) controllerFor(sid string) (*app.Controller, error) {
	a.mu.Lock()
	s, ok := a.sessions[sid]
	a.mu.Unlock()
	if !ok || s.Ctrl == nil {
		return nil, fmt.Errorf("no session %s", sid)
	}
	return s.Ctrl, nil
}

func (a *App) sftpFor(sid string) (*sftpclient.Client, error) {
	a.mu.Lock()
	s, ok := a.sessions[sid]
	a.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("no session %s", sid)
	}
	return s.Ctrl.SFTP()
}

func joinRemote(dir, name string) string {
	if dir == "/" || dir == "" {
		return "/" + name
	}
	return strings.TrimRight(dir, "/") + "/" + name
}

// remoteBase reduces a name typed for the file pane to a safe basename. New
// folder, new file and rename all mean "one entry, here", so anything that would
// address a different place is refused rather than quietly honoured: a "/" moves
// the target into another directory, and "." / ".." name the folder itself or its
// parent. A backslash is left alone because on a Linux server it is an ordinary
// character in a file name.
func remoteBase(name string) (string, error) {
	n := strings.TrimSpace(name)
	switch {
	case n == "":
		return "", fmt.Errorf("name required")
	case n == "." || n == "..":
		return "", fmt.Errorf("%q is not a file name", n)
	case strings.Contains(n, "/"):
		return "", fmt.Errorf("name must not contain %q: %q", "/", n)
	case strings.ContainsRune(n, 0):
		return "", fmt.Errorf("name contains a null byte")
	}
	return n, nil
}
