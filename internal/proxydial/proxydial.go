// Package proxydial dials a TCP target through an outbound SOCKS5 or HTTP
// CONNECT proxy, with no third-party dependency. It exists so Graystone can reach
// SSH servers from behind a corporate or local proxy. The proxy password, when
// one is needed, is supplied at dial time and never persisted by the caller.
package proxydial

import (
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

// Kind selects the proxy protocol. The empty kind means "no proxy": Dial then
// performs a plain TCP connect. "socks5" and "http" are the supported proxies.
type Kind = string

const (
	None   = ""
	SOCKS5 = "socks5"
	HTTP   = "http"
)

// Config describes one outbound proxy. User and Pass are optional and enable
// proxy authentication (SOCKS5 username/password, HTTP Basic).
type Config struct {
	Kind Kind
	Host string
	Port int
	User string
	Pass string
}

// Enabled reports whether a proxy is configured at all.
func (c Config) Enabled() bool { return c.Kind != None && c.Host != "" && c.Port > 0 }

// ValidKind accepts the three known values (empty, socks5, http); anything else
// is rejected so a typo in the saved settings fails loudly at connect time
// rather than silently dialing direct.
func ValidKind(k string) bool {
	switch k {
	case None, SOCKS5, HTTP:
		return true
	}
	return false
}

// Dial connects to target (host:port) through the proxy and returns the raw
// tunneled connection, ready for the SSH handshake. With no proxy configured it
// is a plain TCP dial bounded by timeout.
func (c Config) Dial(target string, timeout time.Duration) (net.Conn, error) {
	if !c.Enabled() {
		d := &net.Dialer{Timeout: timeout}
		return d.Dial("tcp", target)
	}
	// The connection to the proxy itself is bounded by the same timeout; the
	// handshake below then reads replies without an extra deadline so a slow
	// but living proxy is not cut off mid-negotiation.
	d := &net.Dialer{Timeout: timeout}
	conn, err := d.Dial("tcp", net.JoinHostPort(c.Host, strconv.Itoa(c.Port)))
	if err != nil {
		return nil, fmt.Errorf("proxydial: connect to proxy %s: %w", net.JoinHostPort(c.Host, strconv.Itoa(c.Port)), err)
	}
	var herr error
	switch c.Kind {
	case SOCKS5:
		herr = socks5Connect(conn, target, c)
	case HTTP:
		herr = httpConnect(conn, target, c)
	default:
		herr = fmt.Errorf("proxydial: unknown proxy kind %q", c.Kind)
	}
	if herr != nil {
		conn.Close()
		return nil, herr
	}
	return conn, nil
}

// socks5Connect performs the RFC 1928 (plus RFC 1929 auth) handshake and a
// CONNECT to target, leaving conn positioned at the start of the tunnel.
func socks5Connect(conn net.Conn, target string, c Config) error {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return fmt.Errorf("proxydial: bad target %q: %w", target, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 0 || port > 65535 {
		return fmt.Errorf("proxydial: bad target port %q", portStr)
	}

	greet := []byte{0x05, 0x01, 0x00} // VER, NMETHODS, method: no auth
	if c.User != "" {
		greet = []byte{0x05, 0x02, 0x00, 0x02} // offer none + username/password
	}
	if _, err := conn.Write(greet); err != nil {
		return fmt.Errorf("proxydial: socks5 greeting: %w", err)
	}
	var sel [2]byte
	if _, err := io.ReadFull(conn, sel[:]); err != nil {
		return fmt.Errorf("proxydial: socks5 method reply: %w", err)
	}
	if sel[0] != 0x05 {
		return fmt.Errorf("proxydial: socks5 version %d", sel[0])
	}
	switch sel[1] {
	case 0xFF:
		return fmt.Errorf("proxydial: socks5 proxy offered no acceptable auth method")
	case 0x02:
		if err := socks5Auth(conn, c); err != nil {
			return err
		}
	case 0x00:
		// no authentication required
	default:
		return fmt.Errorf("proxydial: socks5 unexpected method %d", sel[1])
	}

	// CONNECT request. Prefer the domain address type (ATYP 0x03) so the proxy
	// resolves the name; use raw IPv4/IPv6 when the host already is one.
	req := []byte{0x05, 0x01, 0x00} // VER, CMD=CONNECT, RSV
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			req = append(req, 0x01)
			req = append(req, v4...)
		} else {
			req = append(req, 0x04)
			req = append(req, ip...)
		}
	} else {
		if len(host) > 255 {
			return fmt.Errorf("proxydial: socks5 host too long")
		}
		req = append(req, 0x03, byte(len(host)))
		req = append(req, host...)
	}
	req = append(req, byte(port>>8), byte(port&0xff))
	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("proxydial: socks5 connect request: %w", err)
	}

	// Reply: VER, REP, RSV, ATYP, then BND.ADDR (variable) and BND.PORT (2).
	var head [4]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		return fmt.Errorf("proxydial: socks5 reply: %w", err)
	}
	if head[0] != 0x05 {
		return fmt.Errorf("proxydial: socks5 reply version %d", head[0])
	}
	if head[1] != 0x00 {
		return fmt.Errorf("proxydial: socks5 connect failed: %s", socks5Error(head[1]))
	}
	if err := skipSocks5Addr(conn, head[3]); err != nil {
		return err
	}
	var bport [2]byte
	if _, err := io.ReadFull(conn, bport[:]); err != nil {
		return fmt.Errorf("proxydial: socks5 reply port: %w", err)
	}
	return nil
}

// socks5Auth runs the RFC 1929 username/password subnegotiation.
func socks5Auth(conn net.Conn, c Config) error {
	if len(c.User) > 255 || len(c.Pass) > 255 {
		return fmt.Errorf("proxydial: socks5 credentials too long")
	}
	msg := []byte{0x01, byte(len(c.User))}
	msg = append(msg, c.User...)
	msg = append(msg, byte(len(c.Pass)))
	msg = append(msg, c.Pass...)
	if _, err := conn.Write(msg); err != nil {
		return fmt.Errorf("proxydial: socks5 auth: %w", err)
	}
	var st [2]byte
	if _, err := io.ReadFull(conn, st[:]); err != nil {
		return fmt.Errorf("proxydial: socks5 auth reply: %w", err)
	}
	if st[1] != 0x00 {
		return fmt.Errorf("proxydial: socks5 proxy rejected the credentials")
	}
	return nil
}

// skipSocks5Addr consumes the BND.ADDR field for the given address type.
func skipSocks5Addr(conn net.Conn, atyp byte) error {
	var n int
	switch atyp {
	case 0x01:
		n = 4 // IPv4
	case 0x03: // domain: length-prefixed
		var l [1]byte
		if _, err := io.ReadFull(conn, l[:]); err != nil {
			return fmt.Errorf("proxydial: socks5 domain length: %w", err)
		}
		n = int(l[0])
	case 0x04:
		n = 16 // IPv6
	default:
		return fmt.Errorf("proxydial: socks5 unknown address type %d", atyp)
	}
	var sink [16]byte
	for n > 0 {
		chunk := n
		if chunk > len(sink) {
			chunk = len(sink)
		}
		if _, err := io.ReadFull(conn, sink[:chunk]); err != nil {
			return fmt.Errorf("proxydial: socks5 bound address: %w", err)
		}
		n -= chunk
	}
	return nil
}

func socks5Error(rep byte) string {
	switch rep {
	case 0x01:
		return "general failure"
	case 0x02:
		return "connection not allowed by ruleset"
	case 0x03:
		return "network unreachable"
	case 0x04:
		return "host unreachable"
	case 0x05:
		return "connection refused by ruleset"
	case 0x06:
		return "TTL expired"
	case 0x07:
		return "command not supported"
	case 0x08:
		return "address type not supported"
	default:
		return "unassigned reply code"
	}
}

// httpConnect issues an HTTP CONNECT request and, on a 2xx reply, leaves conn
// positioned at the start of the tunnel. Header bytes are read one at a time so
// nothing past the terminating CRLF CRLF is consumed from the tunnel stream.
func httpConnect(conn net.Conn, target string, c Config) error {
	// Normalize the authority form; CONNECT wants host:port.
	hostport := target
	if h, p, err := net.SplitHostPort(target); err == nil {
		hostport = net.JoinHostPort(h, p)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n", hostport, hostport)
	if c.User != "" {
		cred := c.User + ":" + c.Pass
		fmt.Fprintf(&b, "Proxy-Authorization: Basic %s\r\n", base64.StdEncoding.EncodeToString([]byte(cred)))
	}
	b.WriteString("Connection: close\r\n\r\n")
	if _, err := conn.Write([]byte(b.String())); err != nil {
		return fmt.Errorf("proxydial: http connect request: %w", err)
	}

	status, err := readHTTPStatusLine(conn)
	if err != nil {
		return err
	}
	parts := strings.SplitN(status, " ", 3)
	if len(parts) < 2 {
		return fmt.Errorf("proxydial: http proxy malformed status line %q", status)
	}
	code, err := strconv.Atoi(parts[1])
	if err != nil || code < 200 || code >= 300 {
		return fmt.Errorf("proxydial: http proxy refused CONNECT: %s", status)
	}
	// Drain the remaining headers up to the blank line, byte by byte so no
	// tunnel payload is swallowed into a buffer we would have to hand back.
	if err := drainHTTPHeaders(conn); err != nil {
		return err
	}
	return nil
}

// readHTTPStatusLine reads the first CRLF-terminated line of the response.
func readHTTPStatusLine(conn net.Conn) (string, error) {
	var line []byte
	var prev byte
	for {
		var b [1]byte
		if _, err := io.ReadFull(conn, b[:]); err != nil {
			return "", fmt.Errorf("proxydial: http proxy reply: %w", err)
		}
		if prev == '\n' {
			break
		}
		line = append(line, b[0])
		prev = b[0]
	}
	return strings.TrimRight(string(line), "\r\n"), nil
}

// drainHTTPHeaders consumes header lines until the blank line that ends the
// header block, reading one byte at a time so no tunnel payload is swallowed
// into a buffer. It stops after seeing CRLF CRLF (or a bare LF LF).
func drainHTTPHeaders(conn net.Conn) error {
	var last [2]byte             // previous two bytes, to spot the terminating blank line
	for i := 0; i < 65536; i++ { // bounded so a chatty proxy cannot spin us
		var b [1]byte
		if _, err := io.ReadFull(conn, b[:]); err != nil {
			return fmt.Errorf("proxydial: http proxy headers: %w", err)
		}
		if (last[0] == '\r' && last[1] == '\n' && b[0] == '\r') || (last[0] == '\n' && b[0] == '\n') {
			// About to complete "\r\n\r\n" or "\n\n": consume one more byte to
			// finish the sequence when it is the CRLF form.
			if last[0] == '\r' {
				var nb [1]byte
				if _, err := io.ReadFull(conn, nb[:]); err != nil {
					return fmt.Errorf("proxydial: http proxy headers: %w", err)
				}
				if nb[0] == '\n' {
					return nil
				}
				last = [2]byte{b[0], nb[0]}
				continue
			}
			return nil
		}
		last[0], last[1] = last[1], b[0]
	}
	return fmt.Errorf("proxydial: http proxy header block too large")
}
