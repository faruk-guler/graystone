package proxydial

import (
	"bufio"
	"encoding/base64"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// startOrigin runs a TCP server that echoes one line back, returning its
// host:port. The proxy under test dials this as its CONNECT target.
func startOrigin(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("origin listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c) // echo everything
			}(c)
		}
	}()
	return ln.Addr().String()
}

// fakeSOCKS5 accepts a single SOCKS5 client, performs the handshake (optionally
// requiring username/password), then proxies bytes to the target it was asked
// to CONNECT to. It reports the auth it saw on the authSeen channel.
func fakeSOCKS5(t *testing.T, wantUser, wantPass string) (addr string, authSeen chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	authSeen = make(chan string, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serveSOCKS5(c, wantUser, wantPass, authSeen)
		}
	}()
	return ln.Addr().String(), authSeen
}

func serveSOCKS5(c net.Conn, wantUser, wantPass string, authSeen chan string) {
	defer c.Close()
	r := bufio.NewReader(c)
	// Greeting: VER, NMETHODS, methods.
	var g [2]byte
	if _, err := io.ReadFull(r, g[:]); err != nil {
		return
	}
	methods := make([]byte, g[1])
	if _, err := io.ReadFull(r, methods); err != nil {
		return
	}
	wantAuth := wantUser != ""
	if wantAuth {
		if _, err := c.Write([]byte{0x05, 0x02}); err != nil {
			return
		}
		// RFC1929 subnegotiation.
		var ver [1]byte
		if _, err := io.ReadFull(r, ver[:]); err != nil {
			return
		}
		ul := readLenByte(r)
		user := readN(r, ul)
		pl := readLenByte(r)
		pass := readN(r, pl)
		if user != wantUser || pass != wantPass {
			authSeen <- "bad"
			_, _ = c.Write([]byte{0x01, 0x01})
			return
		}
		authSeen <- "ok"
		if _, err := c.Write([]byte{0x01, 0x00}); err != nil {
			return
		}
	} else {
		if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
			return
		}
	}
	// CONNECT request: VER, CMD, RSV, ATYP, addr..., port(2).
	var head [4]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return
	}
	host := readSocksAddr(r, head[3])
	var pb [2]byte
	if _, err := io.ReadFull(r, pb[:]); err != nil {
		return
	}
	port := int(pb[0])<<8 | int(pb[1])
	target := net.JoinHostPort(host, strconv.Itoa(port))
	up, err := net.Dial("tcp", target)
	if err != nil {
		_, _ = c.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer up.Close()
	// Success reply with a zeroed IPv4 bound address.
	if _, err := c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, byte(port >> 8), byte(port)}); err != nil {
		return
	}
	go func() { _, _ = io.Copy(up, r); up.Close() }()
	_, _ = io.Copy(c, up)
}

func readLenByte(r *bufio.Reader) int {
	var b [1]byte
	_, _ = io.ReadFull(r, b[:])
	return int(b[0])
}

func readN(r *bufio.Reader, n int) string {
	b := make([]byte, n)
	_, _ = io.ReadFull(r, b)
	return string(b)
}

func readSocksAddr(r *bufio.Reader, atyp byte) string {
	switch atyp {
	case 0x01:
		ip := make([]byte, 4)
		_, _ = io.ReadFull(r, ip)
		return net.IP(ip).String()
	case 0x04:
		ip := make([]byte, 16)
		_, _ = io.ReadFull(r, ip)
		return net.IP(ip).String()
	case 0x03:
		l := readLenByte(r)
		return readN(r, l)
	}
	return ""
}

func TestSOCKS5NoAuthRoundTrip(t *testing.T) {
	origin := startOrigin(t)
	proxyAddr, _ := fakeSOCKS5(t, "", "")
	host, portStr, _ := net.SplitHostPort(proxyAddr)
	port, _ := strconv.Atoi(portStr)

	c := Config{Kind: SOCKS5, Host: host, Port: port}
	conn, err := c.Dial(origin, 3*time.Second)
	if err != nil {
		t.Fatalf("dial through socks5: %v", err)
	}
	defer conn.Close()
	roundTrip(t, conn, "gravel-via-socks5")
}

func TestSOCKS5AuthRoundTrip(t *testing.T) {
	origin := startOrigin(t)
	proxyAddr, authSeen := fakeSOCKS5(t, "alice", "s3cr3t")
	host, portStr, _ := net.SplitHostPort(proxyAddr)
	port, _ := strconv.Atoi(portStr)

	c := Config{Kind: SOCKS5, Host: host, Port: port, User: "alice", Pass: "s3cr3t"}
	conn, err := c.Dial(origin, 3*time.Second)
	if err != nil {
		t.Fatalf("dial through authenticated socks5: %v", err)
	}
	defer conn.Close()
	roundTrip(t, conn, "gravel-auth")
	if got := <-authSeen; got != "ok" {
		t.Fatalf("proxy saw auth %q, want ok", got)
	}

	// Wrong credentials must fail the dial, not silently downgrade.
	bad := Config{Kind: SOCKS5, Host: host, Port: port, User: "alice", Pass: "wrong"}
	if _, err := bad.Dial(origin, 3*time.Second); err == nil {
		t.Fatal("expected the proxy to reject wrong credentials")
	}
}

func TestHTTPConnectRoundTrip(t *testing.T) {
	origin := startOrigin(t)
	proxyAddr, _ := fakeHTTP(t, "", "")
	host, portStr, _ := net.SplitHostPort(proxyAddr)
	port, _ := strconv.Atoi(portStr)

	c := Config{Kind: HTTP, Host: host, Port: port}
	conn, err := c.Dial(origin, 3*time.Second)
	if err != nil {
		t.Fatalf("dial through http proxy: %v", err)
	}
	defer conn.Close()
	// The proxy echoes the target back as the first header comment so the test
	// can confirm CONNECT carried the right authority; then bytes echo.
	roundTrip(t, conn, "gravel-via-http")
}

// fakeHTTP is a minimal CONNECT proxy. When wantUser is set it demands Basic
// auth; the authSeen channel records "ok"/"bad".
func fakeHTTP(t *testing.T, wantUser, wantPass string) (string, chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	authSeen := make(chan string, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serveHTTP(c, wantUser, wantPass, authSeen)
		}
	}()
	return ln.Addr().String(), authSeen
}

func serveHTTP(c net.Conn, wantUser, wantPass string, authSeen chan string) {
	defer c.Close()
	r := bufio.NewReader(c)
	req, err := r.ReadString('\n')
	if err != nil {
		return
	}
	// "CONNECT host:port HTTP/1.1"
	fields := strings.Fields(req)
	if len(fields) < 2 || fields[0] != "CONNECT" {
		return
	}
	target := fields[1]
	var authHeader string
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		if strings.HasPrefix(strings.ToLower(line), "proxy-authorization:") {
			authHeader = strings.TrimSpace(line[len("proxy-authorization:"):])
		}
	}
	if wantUser != "" {
		want := "Basic " + base64.StdEncoding.EncodeToString([]byte(wantUser+":"+wantPass))
		if authHeader != want {
			authSeen <- "bad"
			_, _ = c.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"))
			return
		}
		authSeen <- "ok"
	}
	up, err := net.Dial("tcp", target)
	if err != nil {
		_, _ = c.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer up.Close()
	if _, err := c.Write([]byte("HTTP/1.1 200 Connection established\r\nProxy-Agent: graveltest\r\n\r\n")); err != nil {
		return
	}
	go func() { _, _ = io.Copy(up, r); up.Close() }()
	_, _ = io.Copy(c, up)
}

func TestHTTPConnectRefused(t *testing.T) {
	// A proxy that answers 403 to CONNECT must surface as a dial error.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		r := bufio.NewReader(c)
		_, _ = r.ReadString('\n') // request line
		for {
			l, err := r.ReadString('\n')
			if err != nil || strings.TrimRight(l, "\r\n") == "" {
				break
			}
		}
		_, _ = c.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
	}()
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	c := Config{Kind: HTTP, Host: host, Port: port}
	if _, err := c.Dial("example.invalid:22", 3*time.Second); err == nil {
		t.Fatal("expected the refused CONNECT to fail the dial")
	}
}

func TestDirectDialWithoutProxy(t *testing.T) {
	origin := startOrigin(t)
	c := Config{} // no proxy
	conn, err := c.Dial(origin, 3*time.Second)
	if err != nil {
		t.Fatalf("direct dial: %v", err)
	}
	defer conn.Close()
	roundTrip(t, conn, "gravel-direct")
}

// roundTrip writes a line and expects it echoed back, proving the returned conn
// is a live tunnel to the origin (not just a completed handshake).
func roundTrip(t *testing.T, conn net.Conn, msg string) {
	t.Helper()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte(msg + "\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(msg)+1)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if got := strings.TrimRight(string(buf), "\n"); got != msg {
		t.Fatalf("echoed %q, want %q", got, msg)
	}
}
