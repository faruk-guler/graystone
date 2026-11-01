package sshclient

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"graystone/internal/proxydial"
	"graystone/internal/sessionstore"
)

// InteractFunc asks the user one authentication question in the terminal and
// returns the answer. echo is true for visible prompts like a login name and
// false for secrets. It is the UI bridge for interactive (2FA/MFA) logins.
type InteractFunc func(question string, echo bool) (string, error)

// Credential holds secret inputs supplied at connect time. These values are
// never persisted to disk by Graystone.
type Credential struct {
	Password   string // used for AuthPassword
	Passphrase string // used to decrypt an encrypted private key
	// Proxy, when enabled, routes the initial TCP connection through an
	// outbound SOCKS5/HTTP proxy. Its Pass (if any) is supplied at connect time
	// and never persisted, matching the SSH password policy.
	Proxy proxydial.Config
	// Interact, when non-nil, lets servers that authenticate with
	// keyboard-interactive (OTP/2FA boxes, password-over-kbdint) prompt the
	// user during the handshake. The interactive Connect/ConnectKey flows set
	// it; background dials leave it nil so no handshake can ever block waiting
	// on an answer nobody is there to give.
	Interact InteractFunc
}

// tcpKeepAlivePeriod enables the OS-level keepalive on the bare socket. A
// half-dead link (cable pulled, NAT state dropped) is caught by the TCP stack
// even when the SSH probes below are parked behind a stuck mux.
const tcpKeepAlivePeriod = 30 * time.Second

// kbdIntColdRejectMarker is the x/crypto wording for a server that answers the
// keyboard-interactive initiation with a plain USERAUTH_FAILURE before sending
// any challenge. RFC 4252 allows that reply and OpenSSH's client treats it as a
// method rejection, but the library aborts the whole handshake with this
// protocol error. Servers that fail keyboard-interactive cold are common (root
// login restricted to keys, dropbear without PAM), so Dial retries once without
// the method and surfaces the honest auth result instead of the cryptic error.
const kbdIntColdRejectMarker = "unexpected message type 51 (expected 60)"

// Dial establishes an SSH client for the profile using the given credential and
// TOFU known-hosts store.
func Dial(p sessionstore.Profile, cred Credential, kh *KnownHosts) (*ssh.Client, error) {
	if kh == nil {
		return nil, fmt.Errorf("sshclient: known-hosts store is required (no insecure fallback)")
	}
	client, err := dialOnce(p, cred, kh, nil, true)
	// Only the cold keyboard-interactive rejection re-dials; every other
	// failure (bad password, host key, network) is reported as seen.
	if err != nil && cred.Interact != nil && p.Auth == sessionstore.AuthPassword &&
		strings.Contains(err.Error(), kbdIntColdRejectMarker) {
		if client != nil {
			_ = client.Close()
		}
		return dialOnce(p, cred, kh, nil, false)
	}
	// An old server that cannot agree on any modern algorithm drops the
	// socket mid-handshake; io.EOF is its signature, and an in-process peer
	// that reads x/crypto's own wording before dying arrives wrapped as a
	// handshake failure. Either way one quiet retry with the pre-OpenSSH-7.4
	// algorithm set follows, which connects genuinely ancient hosts instead
	// of failing them with an opaque error. Modern servers never reach this
	// branch: they have the algorithms in common and negotiate normally.
	if err != nil && isAlgorithmNegotiationFailure(err) {
		if client != nil {
			_ = client.Close()
		}
		return dialOnce(p, cred, kh, legacyTransportConfig(), true)
	}
	return client, err
}

// isAlgorithmNegotiationFailure recognises the two shapes a too-old server
// leaves behind: the bare io.EOF of a peer that hung up when KEXINIT found no
// overlap, and x/crypto's "no common algorithm" wrapper for a peer that got
// far enough to be told the same thing back.
func isAlgorithmNegotiationFailure(err error) bool {
	if errors.Is(err, io.EOF) {
		return true
	}
	return strings.Contains(err.Error(), "no common algorithm")
}

// legacyKex, legacyCiphers, legacyMACs and legacyHostKeys spell out the
// algorithm set that ships in golang.org/x/crypto/ssh but left the client
// defaults: group14/group1 SHA-1 and SHA-256 kex, CBC ciphers, plain and
// encrypt-then-match HMACs, and the ssh-rsa host key an OpenSSH-5.x-era
// server has nothing else to offer. Listing them explicitly also pins
// rsa-sha2-256/512 back on in the same attempt: servers old enough to EOF
// our modern-only first offer are usually old enough to miss those too.
var (
	legacyKex = []string{
		"diffie-hellman-group-exchange-sha256",
		"diffie-hellman-group14-sha256",
		"diffie-hellman-group14-sha1",
		"diffie-hellman-group-exchange-sha1",
		"diffie-hellman-group1-sha1",
	}
	legacyCiphers = []string{
		"aes256-ctr", "aes192-ctr", "aes128-ctr",
		"aes256-cbc", "aes192-cbc", "aes128-cbc", "3des-cbc",
	}
	legacyMACs = []string{
		"hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com",
		"hmac-sha2-256", "hmac-sha2-512",
		"hmac-sha1-etm@openssh.com", "hmac-sha1",
	}
	legacyHostKeys = []string{
		"rsa-sha2-512", "rsa-sha2-256", "ssh-rsa",
		"ecdsa-sha2-nistp256", "ssh-dss",
	}
)

// legacyTransportConfig is a fresh ssh.Config filled with the lists above.
// A function, not a shared value: the handshake writes the resolved lists back
// into the config copy it is handed, so every retry must get its own.
func legacyTransportConfig() *ssh.Config {
	return &ssh.Config{
		KeyExchanges: legacyKex,
		Ciphers:      legacyCiphers,
		MACs:         legacyMACs,
	}
}

// dialOnce performs one full connect: TCP (with keepalive), then the SSH
// handshake. withKbdInt adds the keyboard-interactive method to a password
// login; the cold-reject retry drops it. transport, when non-nil, replaces the
// algorithm negotiation sets (see the legacy retry in Dial).
func dialOnce(p sessionstore.Profile, cred Credential, kh *KnownHosts, transport *ssh.Config, withKbdInt bool) (*ssh.Client, error) {
	auth, err := authMethods(p, cred, withKbdInt)
	if err != nil {
		return nil, err
	}
	cfg := &ssh.ClientConfig{
		User:            p.User,
		Auth:            auth,
		HostKeyCallback: kh.HostKeyCallback(),
		Timeout:         15 * time.Second,
	}
	if transport != nil {
		cfg.Config = *transport
		cfg.HostKeyAlgorithms = legacyHostKeys
	}
	d := &net.Dialer{Timeout: cfg.Timeout, KeepAlive: tcpKeepAlivePeriod}
	var nConn net.Conn
	var err2 error
	if cred.Proxy.Enabled() {
		// Reach the server through the configured outbound proxy. The tunneled
		// connection is not a bare TCP socket, so the OS keepalive below is a
		// no-op here; the SSH-layer keepalive still probes the link.
		nConn, err2 = cred.Proxy.Dial(p.Addr(), cfg.Timeout)
	} else {
		nConn, err2 = d.Dial("tcp", p.Addr())
	}
	if err2 != nil {
		return nil, fmt.Errorf("sshclient: dial %s: %w", p.Addr(), err2)
	}
	if tc, ok := nConn.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(tcpKeepAlivePeriod)
	}
	conn, chans, reqs, err := ssh.NewClientConn(nConn, p.Addr(), cfg)
	if err != nil {
		nConn.Close()
		// Interactive TOFU: the host key callback recorded a pending failure. Hand
		// it back unchanged - the UI decides differently for a first contact
		// ("trust this host?") than for a key that no longer matches the one the
		// user confirmed, and collapsing the two would turn a man-in-the-middle
		// into a routine prompt. Parsing the library's wrapped handshake text is
		// neither needed nor reliable here.
		if pending := kh.PendingError(p.Addr()); pending != nil {
			return nil, pending
		}
		return nil, fmt.Errorf("sshclient: dial %s: %w", p.Addr(), err)
	}
	return ssh.NewClient(conn, chans, reqs), nil
}

// AuthFailed reports whether err means the server rejected the supplied
// credentials, as opposed to a network, host-key or protocol problem. Only this
// case is worth asking the user for another password.
//
// x/crypto/ssh builds this error with fmt.Errorf and exports no sentinel value
// or error type, so matching its message is the only handle available. The
// TestAuthFailed* tests dial a real server to pin that wording, so a dependency
// update cannot silently turn the retry loop into a dead branch.
func AuthFailed(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "unable to authenticate")
}

// authMethods builds the SSH auth method list for a profile + credential pair.
// withKbdInt offers keyboard-interactive alongside a password login (see
// keyboardInteractive); key and unknown auth kinds never add the method.
func authMethods(p sessionstore.Profile, cred Credential, withKbdInt bool) ([]ssh.AuthMethod, error) {
	switch p.Auth {
	case sessionstore.AuthKey:
		if p.KeyPath == "" {
			return nil, fmt.Errorf("sshclient: key auth requires a key file path")
		}
		keyFile, err := os.ReadFile(p.KeyPath)
		if err != nil {
			return nil, &KeyFileError{Path: p.KeyPath, Err: fmt.Errorf("read: %w", err)}
		}
		// loadPrivateKey handles OpenSSH keys and PuTTY .ppk files, and tags the
		// failures a better passphrase could fix (see ErrWrongPassphrase).
		signer, err := loadPrivateKey(keyFile, cred.Passphrase, p.KeyPath)
		if err != nil {
			return nil, err
		}
		return []ssh.AuthMethod{ssh.PublicKeys(signer)}, nil
	case sessionstore.AuthPassword, "":
		methods := []ssh.AuthMethod{ssh.Password(cred.Password)}
		// The method is only offered when answers can actually be routed:
		// x/crypto treats a failing keyboard-interactive callback as a protocol
		// error and aborts the whole handshake, which would hide the plain
		// "unable to authenticate" wording the re-prompt loop depends on.
		if withKbdInt && cred.Interact != nil {
			methods = append(methods, keyboardInteractive(cred))
		}
		return methods, nil
	default:
		return nil, fmt.Errorf("sshclient: unknown auth kind %q", p.Auth)
	}
}

// isPasswordQuestion reports whether a keyboard-interactive prompt is the plain
// password box (OpenSSH sends "Password: ", some servers a bare "password").
// Anything else - an OTP or token challenge - must reach the user instead.
func isPasswordQuestion(q string) bool {
	return strings.Contains(strings.ToLower(strings.TrimSpace(q)), "password")
}

// keyboardInteractive answers a server's challenge list. A single password
// question is auto-answered with the credential's password, so ordinary logins
// keep their current one-prompt-per-connection UX while servers that only offer
// keyboard-interactive stop rejecting Graystone outright. Every other question is
// asked through cred.Interact, which authMethods guarantees is non-nil.
func keyboardInteractive(cred Credential) ssh.AuthMethod {
	return ssh.KeyboardInteractive(func(user, instruction string, questions []string, echos []bool) ([]string, error) {
		answers := make([]string, len(questions))
		for i, q := range questions {
			echo := i < len(echos) && echos[i]
			if len(questions) == 1 && isPasswordQuestion(q) {
				answers[i] = cred.Password
				echo = false
				continue
			}
			question := strings.TrimSpace(q)
			if question == "" {
				question = instruction
			}
			if question == "" {
				question = user + "@keyboard-interactive:"
			}
			ans, err := cred.Interact(question, echo)
			if err != nil {
				return nil, err
			}
			answers[i] = ans
		}
		return answers, nil
	})
}
