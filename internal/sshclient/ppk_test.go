package sshclient

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/ssh"

	"graystone/internal/sessionstore"
)

// The .ppk fixtures here are written by this file, which on its own would only
// prove the reader agrees with the writer. Two things make that worth more than
// it looks: the public blob is ssh's own wire encoding rather than something
// this test invented, and TestDialWithPPKKey hands the parsed key to a live
// handshake where the server verifies the signature with the public key - a
// parser that agreed only with itself could never get through.
//
// puttygen is not installed on the development machine, so TestParsePPKRealFiles
// exists to widen the same checks to PuTTY's own output as soon as real .ppk
// files are dropped into testdata/.

// --- building .ppk files ----------------------------------------------------

type keyVariant struct {
	name string
	make func(t *testing.T) any
}

func keyVariants(t *testing.T) []keyVariant {
	t.Helper()
	return []keyVariant{
		{"rsa-2048", func(t *testing.T) any {
			k, err := rsa.GenerateKey(crand.Reader, 2048)
			if err != nil {
				t.Fatalf("rsa key: %v", err)
			}
			return k
		}},
		{"ecdsa-p256", curveKey(elliptic.P256())},
		{"ecdsa-p384", curveKey(elliptic.P384())},
		{"ecdsa-p521", curveKey(elliptic.P521())},
		{"ed25519", func(t *testing.T) any {
			_, priv, err := ed25519.GenerateKey(crand.Reader)
			if err != nil {
				t.Fatalf("ed25519 key: %v", err)
			}
			return priv
		}},
	}
}

// curveKey is the generator shared by the three ECDSA curves, which differ only
// in the curve handed to crypto/ecdsa.
func curveKey(curve elliptic.Curve) func(t *testing.T) any {
	return func(t *testing.T) any {
		k, err := ecdsa.GenerateKey(curve, crand.Reader)
		if err != nil {
			t.Fatalf("ecdsa key: %v", err)
		}
		return k
	}
}

// sshString encodes a field the way the SSH wire format does: uint32 length,
// then the bytes.
func sshString(b []byte) []byte {
	out := make([]byte, 4+len(b))
	binary.BigEndian.PutUint32(out, uint32(len(b)))
	copy(out[4:], b)
	return out
}

// mpint encodes a number as SSH does, prefixing a zero byte when the top bit is
// set so the value stays positive.
func mpint(v *big.Int) []byte {
	if v.Sign() == 0 {
		return sshString(nil)
	}
	return mpintBytes(v.Bytes())
}

func mpintBytes(b []byte) []byte {
	if len(b) > 0 && b[0]&0x80 != 0 {
		b = append([]byte{0}, b...)
	}
	return sshString(b)
}

// privateBlob is the sequence PuTTY stores for each key type: RSA keeps d and
// both primes, ECDSA only the scalar, Ed25519 the seed as a number.
func privateBlob(t *testing.T, key any) []byte {
	t.Helper()
	switch k := key.(type) {
	case *rsa.PrivateKey:
		blob := mpint(k.D)
		blob = append(blob, mpint(k.Primes[0])...)
		return append(blob, mpint(k.Primes[1])...)
	case *ecdsa.PrivateKey:
		return mpint(k.D)
	case ed25519.PrivateKey:
		return mpintBytes(k.Seed())
	}
	t.Fatalf("unsupported key type %T", key)
	return nil
}

// buildPPK renders a key in PuTTY's text framing. mac is written into the MAC
// line when non-empty; the loader ignores that field, and the test that passes
// garbage through it keeps that decision from becoming an accident.
func buildPPK(t *testing.T, key any, version int, passphrase, mac string) string {
	t.Helper()
	return buildPPKAs(t, key, version, passphrase, mac, "")
}

// buildPPKAs also lets a test claim a different algorithm in both the header and
// the public blob, which is how the unsupported-type branches get a file that is
// otherwise well formed.
func buildPPKAs(t *testing.T, key any, version int, passphrase, mac, algoOverride string) string {
	t.Helper()

	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	pubBlob := signer.PublicKey().Marshal()
	algo := signer.PublicKey().Type()
	if algoOverride != "" {
		// Swap only the algorithm name; the key material behind it stays the same.
		name := sshString([]byte(algo))
		pubBlob = append(sshString([]byte(algoOverride)), pubBlob[len(name):]...)
		algo = algoOverride
	}
	priv := privateBlob(t, key)

	encryption := "none"
	var kdf []string
	if passphrase != "" {
		encryption = "aes256-cbc"
		// PuTTY pads the wrapped blob to whole AES blocks and the loader stops
		// reading once the fields are consumed, so zero padding has the same
		// shape as the real thing.
		if pad := len(priv) % aes.BlockSize; pad != 0 {
			priv = append(priv, make([]byte, aes.BlockSize-pad)...)
		}
		var keyBytes, iv []byte
		if version == 2 {
			keyBytes = ppkV2Key(passphrase, 0)
			iv = make([]byte, aes.BlockSize)
		} else {
			salt := make([]byte, 16)
			if _, err := crand.Read(salt); err != nil {
				t.Fatalf("salt: %v", err)
			}
			// Cheap but genuine Argon2 settings: what is under test is which
			// slice of the 80-byte block becomes key and IV, not Argon2 itself.
			derived := argon2.IDKey([]byte(passphrase), salt, 2, 1024, 1, ppkDerivedBytes)
			keyBytes = derived[:ppkKeyBytes]
			iv = derived[ppkKeyBytes : ppkKeyBytes+ppkIVBytes]
			kdf = []string{
				"Key-Derivation: Argon2id",
				"Argon2-Memory: 1024",
				"Argon2-Passes: 2",
				"Argon2-Parallelism: 1",
				"Argon2-Salt: " + hex.EncodeToString(salt),
			}
		}
		block, err := aes.NewCipher(keyBytes)
		if err != nil {
			t.Fatalf("cipher: %v", err)
		}
		out := make([]byte, len(priv))
		copy(out, priv)
		cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, out)
		priv = out
	}

	lines := []string{
		fmt.Sprintf("PuTTY-User-Key-File-%d: %s", version, algo),
		"Encryption: " + encryption,
		"Comment: graystone test key",
	}
	lines = append(lines, kdf...)
	lines = append(lines, numberedBlob("Public", pubBlob)...)
	lines = append(lines, numberedBlob("Private", priv)...)
	if mac != "" {
		if version == 2 {
			lines = append(lines, "Private-MAC: "+mac)
		} else {
			lines = append(lines, "MAC: "+mac)
		}
	}
	return strings.Join(lines, "\n") + "\n"
}

// numberedBlob base64s a blob and wraps it as the -Lines header plus body that
// PuTTY writes.
func numberedBlob(name string, blob []byte) []string {
	b64 := base64.StdEncoding.EncodeToString(blob)
	var body []string
	for i := 0; i < len(b64); i += 64 {
		end := min(i+64, len(b64))
		body = append(body, b64[i:end])
	}
	return append([]string{fmt.Sprintf("%s-Lines: %d", name, len(body))}, body...)
}

// setHeader rewrites one header's value, which is how the refusal tests build a
// file that is valid except for the field under test.
func setHeader(t *testing.T, text, name, value string) string {
	t.Helper()
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		if _, ok := strings.CutPrefix(line, name+":"); ok {
			lines[i] = name + ": " + value
			return strings.Join(lines, "\n")
		}
	}
	t.Fatalf("fixture has no %s header", name)
	return ""
}

// corruptBody replaces the first base64 line under a -Lines header with bytes no
// decoder can accept.
func corruptBody(t *testing.T, text, header string) string {
	t.Helper()
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		if strings.HasPrefix(line, header) && i+1 < len(lines) {
			lines[i+1] = "!!!! not base64 !!!!"
			return strings.Join(lines, "\n")
		}
	}
	t.Fatalf("fixture has no %s header", header)
	return ""
}

func ed25519Key(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(crand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	return priv
}

// --- the format matrix ------------------------------------------------------

// TestParsePPK walks every combination the loader claims to read: both file
// versions, all three key algorithms, stored plain and wrapped.
func TestParsePPK(t *testing.T) {
	variants := keyVariants(t)
	for _, version := range []int{2, 3} {
		for _, v := range variants {
			key := v.make(t)
			want, err := ssh.NewSignerFromKey(key)
			if err != nil {
				t.Fatalf("want signer: %v", err)
			}
			for _, passphrase := range []string{"", "a test passphrase"} {
				label := "plain"
				if passphrase != "" {
					label = "wrapped"
				}
				t.Run(fmt.Sprintf("v%d/%s/%s", version, v.name, label), func(t *testing.T) {
					text := buildPPK(t, key, version, passphrase, "")
					signer, err := parsePPK([]byte(text), passphrase)
					if err != nil {
						t.Fatalf("parsePPK: %v", err)
					}
					if !bytes.Equal(signer.PublicKey().Marshal(), want.PublicKey().Marshal()) {
						t.Errorf("public half mismatch for %s", v.name)
					}
					if signer.PublicKey().Type() != want.PublicKey().Type() {
						t.Errorf("type = %q, want %q", signer.PublicKey().Type(), want.PublicKey().Type())
					}
				})
			}
		}
	}
}

// TestParsePPKCRLFFraming matters because PuTTY writes CRLF files, and a line
// ending leaking into the framing would break every one of them.
func TestParsePPKCRLFFraming(t *testing.T) {
	priv := ed25519Key(t)
	text := buildPPK(t, priv, 2, "", "")
	signer, err := parsePPK([]byte(strings.ReplaceAll(text, "\n", "\r\n")), "")
	if err != nil {
		t.Fatalf("CRLF file: %v", err)
	}
	if signer.PublicKey().Type() != "ssh-ed25519" {
		t.Fatalf("unexpected key type %q", signer.PublicKey().Type())
	}
}

// TestParsePPKWrongPassphrase pins the behaviour ConnectKey's re-prompt loop is
// built on: a wrapped key opened with the wrong passphrase is reported as a
// passphrase problem for every algorithm, because that is what the user can fix.
func TestParsePPKWrongPassphrase(t *testing.T) {
	const right = "the-right-one"
	variants := keyVariants(t)
	for _, version := range []int{2, 3} {
		for _, v := range variants {
			key := v.make(t)
			t.Run(fmt.Sprintf("v%d/%s", version, v.name), func(t *testing.T) {
				text := buildPPK(t, key, version, right, "")
				_, err := parsePPK([]byte(text), "typed something else")
				if !errors.Is(err, ErrWrongPassphrase) {
					t.Fatalf("err = %v, want it to match ErrWrongPassphrase", err)
				}
				// The detail survives, so the log still says what broke.
				if !strings.Contains(err.Error(), "passphrase") {
					t.Errorf("message should name the passphrase: %q", err)
				}
			})
		}
	}
}

// TestParsePPKIgnoresMACField documents a deliberate gap: the file's MAC is not
// verified. The public-half comparison covers what that MAC is for, and checking
// it would only add a way to reject a valid key.
func TestParsePPKIgnoresMACField(t *testing.T) {
	priv := ed25519Key(t)
	for _, version := range []int{2, 3} {
		text := buildPPK(t, priv, version, "", "00000000000000000000000000000000")
		if _, err := parsePPK([]byte(text), ""); err != nil {
			t.Fatalf("v%d with a garbage MAC line: %v", version, err)
		}
	}
}

// --- refusing what must not load -------------------------------------------

func TestParsePPKRejectsBadFiles(t *testing.T) {
	priv := ed25519Key(t)
	valid := buildPPK(t, priv, 2, "", "")

	cases := []struct {
		name    string
		text    string
		wantSub string
	}{
		{"no header at all", "Encryption: none\nComment: x\n", "unknown or missing format header"},
		{"empty file", "", "unknown or missing format header"},
		{"version 1", setHeader(t, valid, "PuTTY-User-Key-File-2", "ssh-ed25519"), ""}, // replaced below
		{"no algorithm", setHeader(t, valid, "PuTTY-User-Key-File-2", ""), "no key algorithm"},
		{"line count larger than the file", setHeader(t, valid, "Public-Lines", "9999"), "says 9999 lines"},
		{"private blob is not base64", corruptBody(t, valid, "Private-Lines:"), "private blob"},
		{"unsupported encryption", setHeader(t, valid, "Encryption", "3des-cbc"), "unsupported encryption"},
		{"dsa algorithm", buildPPKAs(t, priv, 2, "", "", "ssh-dss"), "DSA keys are not supported"},
		{"header disagrees with the blob", setHeader(t, valid, "PuTTY-User-Key-File-2", "ssh-rsa"), "but the header says"},
		{"unknown algorithm", buildPPKAs(t, priv, 2, "", "", "ssh-secsh"), "unsupported key algorithm"},
		{"oversized file", valid + "Comment: " + strings.Repeat("x", ppkMaxFileBytes+1) + "\n", "the limit is"},
	}
	for _, tc := range cases {
		if tc.name == "version 1" {
			// The version lives in the header name, not its value.
			tc.text, tc.wantSub = strings.Replace(valid, "PuTTY-User-Key-File-2:", "PuTTY-User-Key-File-1:", 1), "format v1"
		}
		t.Run(tc.name, func(t *testing.T) {
			_, err := parsePPK([]byte(tc.text), "")
			if err == nil {
				t.Fatal("parsePPK must refuse this file")
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("err = %q, want it to mention %q", err, tc.wantSub)
			}
			// A file broken on its own terms must never be reported as a
			// passphrase problem: that would send the user into a retry loop
			// that cannot succeed.
			if errors.Is(err, ErrWrongPassphrase) {
				t.Errorf("a broken file is not a passphrase failure: %v", err)
			}
		})
	}
}

// TestParsePPKArgon2Limits checks the ceilings that stop a hand-made file from
// ordering a gigantic derivation, and that a rejected parameter stays the file's
// own problem rather than becoming the user's.
func TestParsePPKArgon2Limits(t *testing.T) {
	priv := ed25519Key(t)
	const pass = "pp"
	base := buildPPK(t, priv, 3, pass, "")

	cases := []struct {
		name    string
		text    string
		wantSub string
	}{
		{"memory above the ceiling", setHeader(t, base, "Argon2-Memory", fmt.Sprint(ppkMaxMemoryKiB+1)), "Argon2-Memory"},
		{"memory zero", setHeader(t, base, "Argon2-Memory", "0"), "Argon2-Memory"},
		{"memory not a number", setHeader(t, base, "Argon2-Memory", "lots"), "cannot parse Argon2-Memory"},
		{"passes above the ceiling", setHeader(t, base, "Argon2-Passes", fmt.Sprint(ppkMaxPasses+1)), "Argon2-Passes"},
		{"parallelism above the ceiling", setHeader(t, base, "Argon2-Parallelism", fmt.Sprint(ppkMaxParallelism+1)), "Argon2-Parallelism"},
		{"unknown derivation", setHeader(t, base, "Key-Derivation", "scrypt"), "unsupported key derivation"},
		{"missing salt", setHeader(t, base, "Argon2-Salt", ""), "no Argon2-Salt"},
		{"salt is not hex", setHeader(t, base, "Argon2-Salt", "zz"), "cannot parse Argon2-Salt"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parsePPK([]byte(tc.text), pass)
			if err == nil {
				t.Fatal("parsePPK must refuse these parameters")
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("err = %q, want it to mention %q", err, tc.wantSub)
			}
			if errors.Is(err, ErrWrongPassphrase) {
				t.Errorf("an impossible parameter is the file's fault, not the user's: %v", err)
			}
		})
	}
}

// --- the real thing --------------------------------------------------------

// TestDialWithPPKKey is the proof that this format work is worth anything: a
// wrapped v2 .ppk written to disk, loaded through the same path a profile uses,
// and taken through a live handshake where the server checks the signature with
// the public key.
func TestDialWithPPKKey(t *testing.T) {
	priv := ed25519Key(t)
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	const pass = "ppk-test-passphrase"

	dir := t.TempDir()
	path := filepath.Join(dir, "graystone-test.ppk")
	if err := os.WriteFile(path, []byte(buildPPK(t, priv, 2, pass, "00")), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	addr := startAuthServer(t, testOptions{AuthorizedKey: signer.PublicKey()})
	prof := profileForAddr(t, addr)
	prof.Auth = sessionstore.AuthKey
	prof.KeyPath = path

	kh := NewKnownHosts(dir)
	if err := kh.Load(); err != nil {
		t.Fatalf("known hosts: %v", err)
	}
	client, err := dialTrusted(t, prof, Credential{Passphrase: pass}, kh)
	if err != nil {
		t.Fatalf("dial with a .ppk: %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// The same profile with a mistyped passphrase must be classified as worth
	// asking again, which is what makes ConnectKey's in-place retry reachable for
	// key logins instead of leaving it dead code.
	var keyErr *KeyFileError
	_, err = Dial(prof, Credential{Passphrase: "typed wrong"}, kh)
	if !errors.As(err, &keyErr) {
		t.Fatalf("err = %v, want a KeyFileError", err)
	}
	if !errors.Is(keyErr, ErrWrongPassphrase) {
		t.Errorf("err = %v, want it to match ErrWrongPassphrase", keyErr)
	}
	if !strings.Contains(keyErr.Error(), path) {
		t.Errorf("the message should name the key file the user picked: %v", keyErr)
	}

	// An unreadable path is a hard stop, not something to retype against.
	bad := prof
	bad.KeyPath = filepath.Join(dir, "does-not-exist.ppk")
	_, err = Dial(bad, Credential{Passphrase: pass}, kh)
	keyErr = nil
	if !errors.As(err, &keyErr) {
		t.Fatalf("err = %v, want a KeyFileError", err)
	}
	if errors.Is(keyErr, ErrWrongPassphrase) {
		t.Errorf("a missing file is not a passphrase failure: %v", keyErr)
	}
}

// TestParsePPKRealFiles extends the matrix to keys written by PuTTYgen itself.
// It stays skipped until real files are placed in testdata/, each optionally
// paired with a <name>.pass file holding nothing but its passphrase.
func TestParsePPKRealFiles(t *testing.T) {
	matches, err := filepath.Glob(filepath.Join("testdata", "*.ppk"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(matches) == 0 {
		t.Skip("no testdata/*.ppk fixtures: put PuTTYgen-generated keys here to check this test against the real writer")
	}
	for _, path := range matches {
		t.Run(filepath.Base(path), func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			pass := ""
			if p, err := os.ReadFile(strings.TrimSuffix(path, ".ppk") + ".pass"); err == nil {
				pass = strings.TrimSpace(string(p))
			}
			if _, err := parsePPK(data, pass); err != nil {
				t.Fatalf("parse %s: %v", path, err)
			}
		})
	}
}

// --- the OpenSSH path must not regress -------------------------------------

// TestLoadPrivateKeyOpenSSHKeepsWorking guards the half of key support that
// already worked: the dispatcher added for .ppk must leave PEM and the newer
// OpenSSH format alone, including how a protected key is reported when no
// passphrase was given.
func TestLoadPrivateKeyOpenSSHKeepsWorking(t *testing.T) {
	priv := ed25519Key(t)
	want, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	plainBlock, err := ssh.MarshalPrivateKey(priv, "plain")
	if err != nil {
		t.Fatalf("marshal plain: %v", err)
	}
	plain := pem.EncodeToMemory(plainBlock)

	wrappedBlock, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "wrapped", []byte("pp"))
	if err != nil {
		t.Fatalf("marshal wrapped: %v", err)
	}
	wrapped := pem.EncodeToMemory(wrappedBlock)

	if isPPK(plain) || isPPK(wrapped) {
		t.Error("an OpenSSH key file must not be routed to the .ppk reader")
	}

	signer, err := loadPrivateKey(plain, "", "id_ed25519")
	if err != nil {
		t.Fatalf("plain key: %v", err)
	}
	if !bytes.Equal(signer.PublicKey().Marshal(), want.PublicKey().Marshal()) {
		t.Error("plain key loaded the wrong half")
	}

	if _, err := loadPrivateKey(wrapped, "pp", "id_ed25519"); err != nil {
		t.Fatalf("wrapped key with its passphrase: %v", err)
	}
	for _, tc := range []struct{ name, pass string }{
		{"wrong passphrase", "nope"},
		{"no passphrase given", ""},
	} {
		_, err := loadPrivateKey(wrapped, tc.pass, "id_ed25519")
		var keyErr *KeyFileError
		if !errors.As(err, &keyErr) {
			t.Fatalf("%s: err = %v, want KeyFileError", tc.name, err)
		}
		if !errors.Is(keyErr, ErrWrongPassphrase) {
			t.Errorf("%s: err = %v, want it to match ErrWrongPassphrase", tc.name, err)
		}
	}

	_, err = loadPrivateKey([]byte("not any key format"), "", "junk")
	var keyErr *KeyFileError
	if !errors.As(err, &keyErr) {
		t.Fatalf("err = %v, want KeyFileError", err)
	}
	if errors.Is(keyErr, ErrWrongPassphrase) {
		t.Errorf("junk is not a passphrase problem: %v", keyErr)
	}
}

func TestIsPPK(t *testing.T) {
	cases := []struct {
		name string
		data string
		want bool
	}{
		{"v2", "PuTTY-User-Key-File-2: ssh-rsa\n", true},
		{"v3", "PuTTY-User-Key-File-3: ssh-ed25519\n", true},
		{"leading blank line", "\n\r\nPuTTY-User-Key-File-2: ssh-rsa\n", true},
		{"openssh pem", "-----BEGIN OPENSSH PRIVATE KEY-----\n", false},
		{"near miss", "PuTTY\n", false},
		{"empty", "", false},
	}
	for _, tc := range cases {
		if got := isPPK([]byte(tc.data)); got != tc.want {
			t.Errorf("%s: isPPK = %v, want %v", tc.name, got, tc.want)
		}
	}
}
