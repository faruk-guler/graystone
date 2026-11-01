package sshclient

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/ssh"
)

// ppkMagic begins every PuTTY private key file, immediately followed by the
// format version ("PuTTY-User-Key-File-2: ssh-rsa"). golang.org/x/crypto/ssh
// only reads PEM and OpenSSH key files - and PuTTY itself cannot read those, so
// a key generated with PuTTYgen exists only in this format. Without a reader for
// it the key picker would offer *.ppk and then fail on every file it accepted.
const ppkMagic = "PuTTY-User-Key-File-"

// Ceilings on what a key file is allowed to ask for. The parameters that decide
// how much memory and CPU the passphrase derivation costs are read out of the
// file itself, and that file may have been handed to the user by somebody else.
// PuTTYgen's own presets sit well inside these numbers - a v3 key normally asks
// for tens of megabytes - so the ceiling exists only to stop a hand-made file
// from demanding a multi-gigabyte allocation on the user's machine. Reaching one
// is reported as a limit, not as a wrong passphrase, because a genuinely that
// expensive key is possible: the fix is to re-save it in PuTTYgen, not to retype.
const (
	ppkMaxFileBytes   = 1 << 20 // real keys are a few KB
	ppkMaxMemoryKiB   = 1024 * 1024
	ppkMaxPasses      = 64
	ppkMaxParallelism = 16
	// shortcut: 1 GiB derivation ceiling, raise it only if a real PuTTYgen preset
	// is ever reported as needing more.

	// A v3 derivation yields the AES key, the IV and the MAC key in one block.
	ppkDerivedBytes = 80
	ppkKeyBytes     = 32
	ppkIVBytes      = 16
)

// isPPK reports whether the file is a PuTTY private key rather than a PEM or
// OpenSSH one, so loadPrivateKey can pick the right reader.
func isPPK(data []byte) bool {
	return bytes.HasPrefix(bytes.TrimSpace(data), []byte(ppkMagic))
}

// ppkKey is a parsed .ppk file: its framing, the private blob (still encrypted
// until unlock) and everything needed to derive the key that opens it.
type ppkKey struct {
	version    int
	algo       string
	encryption string
	pub        []byte
	priv       []byte

	// Only used by format v3, which replaces v2's SHA-1 derivation with Argon2.
	kdfAlgo      string
	kdfMemoryKiB int
	kdfPasses    int
	kdfThreads   int
	kdfSalt      []byte
}

// parsePPK turns a PuTTY .ppk file (format v2 and v3, RSA / ECDSA / Ed25519,
// optionally aes256-cbc encrypted) into an SSH signer.
//
// PuTTY also stores a MAC over the key's own fields. It is parsed but
// deliberately not checked: signer already proves the private half produces the
// public half sitting in the same file, which is the property that MAC exists to
// give - and it holds for all three algorithms at once, while reproducing
// PuTTY's exact HMAC construction would only add a new way to reject a perfectly
// good key. A test loads a file whose MAC line is garbage to keep that decision
// from silently turning into an oversight.
func parsePPK(data []byte, passphrase string) (ssh.Signer, error) {
	k, err := readPPK(data)
	if err != nil {
		return nil, err
	}
	priv, decrypted, err := k.unlock(passphrase)
	if err != nil {
		// Nothing was decrypted yet, so this is the file's own fault: an
		// unsupported encryption or derivation, a bad length. Retyping a
		// passphrase cannot change any of it, and saying so is the honest report.
		return nil, err
	}
	signer, err := k.signer(priv)
	if err != nil {
		if decrypted {
			// A wrapped blob that unlocked but yields garbage fields, impossible
			// scalars or a public half that does not match has exactly one
			// explanation for somebody typing at a prompt.
			return nil, wrongPassphrase(err)
		}
		return nil, err
	}
	return signer, nil
}

// wrongPassphrase re-labels a post-decode failure as the passphrase problem it
// really is, keeping the detail that tells a log reader what broke.
func wrongPassphrase(err error) error {
	return fmt.Errorf("%w: %s", ErrWrongPassphrase, strings.TrimPrefix(err.Error(), "ppk: "))
}

// readPPK splits the text framing from the two base64 blobs and validates every
// number the rest of the loader trusts.
func readPPK(data []byte) (*ppkKey, error) {
	if len(data) > ppkMaxFileBytes {
		return nil, fmt.Errorf("ppk: file is %d bytes, the limit is %d", len(data), ppkMaxFileBytes)
	}
	k := &ppkKey{}
	var pubB64, privB64 strings.Builder
	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")

	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		colon := strings.IndexByte(line, ':')
		if colon <= 0 {
			continue
		}
		// The base64 body never reaches this branch: the *-Lines cases below
		// consume their own lines and step the loop past them.
		name, val := line[:colon], strings.TrimSpace(line[colon+1:])
		var err error
		switch {
		case strings.HasPrefix(name, ppkMagic):
			var v int
			v, err = strconv.Atoi(strings.TrimPrefix(name, ppkMagic))
			if err == nil {
				k.version, k.algo = v, val
			} else {
				err = fmt.Errorf("ppk: cannot read format version from %q", name)
			}
		case name == "Encryption":
			k.encryption = val
		case name == "Public-Lines", name == "Private-Lines":
			var n int
			n, err = strconv.Atoi(val)
			if err == nil && n < 0 {
				err = fmt.Errorf("ppk: bad %s %q", name, val)
			}
			if err == nil && n > len(lines)-i-1 {
				err = fmt.Errorf("ppk: %s says %d lines but the file has %d left", name, n, len(lines)-i-1)
			}
			if err == nil {
				dst := &pubB64
				if name == "Private-Lines" {
					dst = &privB64
				}
				for j := 1; j <= n; j++ {
					dst.WriteString(strings.TrimSpace(lines[i+j]))
				}
				i += n
			}
		case name == "Key-Derivation":
			k.kdfAlgo = val
		case name == "Argon2-Memory":
			k.kdfMemoryKiB, err = strconv.Atoi(val)
		case name == "Argon2-Passes":
			k.kdfPasses, err = strconv.Atoi(val)
		case name == "Argon2-Parallelism":
			k.kdfThreads, err = strconv.Atoi(val)
		case name == "Argon2-Salt":
			k.kdfSalt, err = hex.DecodeString(val)
		default:
			// Comment, MAC / Private-MAC and Access-Certificate are not needed
			// to use the key, so they are ignored rather than rejected.
		}
		if err != nil {
			return nil, fmt.Errorf("ppk: cannot parse %s: %w", name, err)
		}
	}

	switch k.version {
	case 2, 3:
	case 1:
		return nil, errors.New("ppk: format v1 is decades old; open the key in PuTTYgen and save it again")
	default:
		return nil, fmt.Errorf("ppk: unknown or missing format header (found version %d)", k.version)
	}
	if k.algo == "" {
		return nil, errors.New("ppk: no key algorithm in the format header")
	}
	if k.encryption == "" {
		k.encryption = "none"
	}
	if k.version == 3 && k.encryption != "none" {
		if err := k.checkArgon2(); err != nil {
			return nil, err
		}
	}

	pub, err := base64.StdEncoding.DecodeString(pubB64.String())
	if err != nil {
		return nil, fmt.Errorf("ppk: public blob: %w", err)
	}
	priv, err := base64.StdEncoding.DecodeString(privB64.String())
	if err != nil {
		return nil, fmt.Errorf("ppk: private blob: %w", err)
	}
	if len(pub) == 0 || len(priv) == 0 {
		return nil, errors.New("ppk: file is missing its public or private blob")
	}
	k.pub, k.priv = pub, priv
	return k, nil
}

// checkArgon2 rejects the derivation parameters before any of them is used.
func (k *ppkKey) checkArgon2() error {
	switch strings.ToLower(k.kdfAlgo) {
	case "argon2id", "argon2i":
	default:
		return fmt.Errorf("ppk: unsupported key derivation %q", k.kdfAlgo)
	}
	if k.kdfMemoryKiB <= 0 || k.kdfMemoryKiB > ppkMaxMemoryKiB {
		return fmt.Errorf("ppk: Argon2-Memory %d is outside 1..%d KiB", k.kdfMemoryKiB, ppkMaxMemoryKiB)
	}
	if k.kdfPasses <= 0 || k.kdfPasses > ppkMaxPasses {
		return fmt.Errorf("ppk: Argon2-Passes %d is outside 1..%d", k.kdfPasses, ppkMaxPasses)
	}
	if k.kdfThreads <= 0 || k.kdfThreads > ppkMaxParallelism {
		return fmt.Errorf("ppk: Argon2-Parallelism %d is outside 1..%d", k.kdfThreads, ppkMaxParallelism)
	}
	if len(k.kdfSalt) == 0 {
		return errors.New("ppk: no Argon2-Salt in the file")
	}
	return nil
}

// unlock returns the private blob, decrypting it when the file says it is
// wrapped, along with whether a decryption actually happened - the caller uses
// that to tell a broken file apart from a mistyped passphrase. A copy is
// decrypted so the ciphertext held in ppkKey stays intact.
func (k *ppkKey) unlock(passphrase string) ([]byte, bool, error) {
	if k.encryption == "none" {
		return k.priv, false, nil
	}
	if k.encryption != "aes256-cbc" {
		return nil, false, fmt.Errorf("ppk: unsupported encryption %q", k.encryption)
	}
	if len(k.priv)%aes.BlockSize != 0 {
		return nil, false, fmt.Errorf("ppk: encrypted blob is %d bytes, not a multiple of the %d-byte block size", len(k.priv), aes.BlockSize)
	}
	key, iv, err := k.deriveKeys(passphrase)
	if err != nil {
		return nil, false, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, false, fmt.Errorf("ppk: aes: %w", err)
	}
	out := make([]byte, len(k.priv))
	copy(out, k.priv)
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, out)
	return out, true, nil
}

// deriveKeys produces the AES key and IV for the file's own derivation. v2 uses
// PuTTY's SHA-1 counter construction with an all-zero IV; v3 uses Argon2 and
// splits one 80-byte block into key, IV and MAC key.
func (k *ppkKey) deriveKeys(passphrase string) (key, iv []byte, err error) {
	if k.version == 2 {
		return ppkV2Key(passphrase, 0), make([]byte, aes.BlockSize), nil
	}
	var derived []byte
	switch strings.ToLower(k.kdfAlgo) {
	case "argon2id":
		derived = argon2.IDKey([]byte(passphrase), k.kdfSalt, uint32(k.kdfPasses), uint32(k.kdfMemoryKiB), uint8(k.kdfThreads), ppkDerivedBytes)
	case "argon2i":
		derived = argon2.Key([]byte(passphrase), k.kdfSalt, uint32(k.kdfPasses), uint32(k.kdfMemoryKiB), uint8(k.kdfThreads), ppkDerivedBytes)
	default:
		return nil, nil, fmt.Errorf("ppk: unsupported key derivation %q", k.kdfAlgo)
	}
	return derived[:ppkKeyBytes], derived[ppkKeyBytes : ppkKeyBytes+ppkIVBytes], nil
}

// ppkV2Key is PuTTY's v2 derivation: concatenate SHA-1(counter || passphrase)
// for counters starting at counterStart until 32 bytes are in hand.
//
// SHA-1 is not a choice Graystone makes - it is the construction PuTTY defined for
// this format, and using anything else would fail every real v2 key file. The
// MAC key uses the same construction from counter 1 and is not needed here,
// because the file's MAC is not verified (see parsePPK).
func ppkV2Key(passphrase string, counterStart uint32) []byte {
	var md []byte
	for i := counterStart; len(md) < ppkKeyBytes; i++ {
		h := sha1.New()
		_ = binary.Write(h, binary.BigEndian, i)
		h.Write([]byte(passphrase))
		md = h.Sum(md)
	}
	return md[:ppkKeyBytes]
}

// signer builds a signer from the private blob and proves it belongs to the
// public blob that sits in the same file.
func (k *ppkKey) signer(priv []byte) (ssh.Signer, error) {
	// Both blobs are SSH wire format, so the public one opens with the algorithm
	// name. It has to be consumed before any number is read, and it is checked
	// against the header rather than trusted: reading the name as a number is how
	// an RSA key ends up with an exponent of 20 quadrillion.
	pub := &blobReader{b: k.pub}
	token, err := pub.str()
	if err != nil {
		return nil, fmt.Errorf("ppk: public blob algorithm name: %w", err)
	}
	if string(token) != k.algo {
		return nil, fmt.Errorf("ppk: public blob is %q but the header says %q", token, k.algo)
	}

	// Dispatch on the declared type before anything is parsed out of the blobs,
	// so a DSA or unknown key is reported as the unsupported key it is instead of
	// as a blob that failed to decode.
	var cryptoKey any
	switch k.algo {
	case "ssh-rsa":
		cryptoKey, err = k.rsaKey(pub, priv)
	case "ssh-ed25519":
		cryptoKey, err = k.ed25519Key(priv)
	case "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521":
		cryptoKey, err = k.ecdsaKey(k.algo, priv)
	case "ssh-dss":
		return nil, errors.New("ppk: DSA keys are not supported; a server that needs one cannot offer a modern host key either")
	default:
		return nil, fmt.Errorf("ppk: unsupported key algorithm %q", k.algo)
	}
	if err != nil {
		return nil, err
	}

	signer, err := ssh.NewSignerFromKey(cryptoKey)
	if err != nil {
		return nil, fmt.Errorf("ppk: %w", err)
	}
	want, err := ssh.ParsePublicKey(k.pub)
	if err != nil {
		return nil, fmt.Errorf("ppk: public blob: %w", err)
	}
	if !bytes.Equal(signer.PublicKey().Marshal(), want.Marshal()) {
		// The classic symptom of a wrong passphrase: plausible-looking numbers
		// that belong to a different key. parsePPK turns it into ErrWrongPassphrase.
		return nil, errors.New("ppk: the key's private half does not match its public half")
	}
	return signer, nil
}

// rsaKey reads the RSA numbers out of the two blobs. pub is already positioned
// past the algorithm name (see signer).
func (k *ppkKey) rsaKey(pub *blobReader, priv []byte) (*rsa.PrivateKey, error) {
	e, err := pub.mpint()
	if err != nil {
		return nil, fmt.Errorf("ppk: rsa exponent: %w", err)
	}
	n, err := pub.mpint()
	if err != nil {
		return nil, fmt.Errorf("ppk: rsa modulus: %w", err)
	}
	p := &blobReader{b: priv}
	d, err := p.mpint()
	if err != nil {
		return nil, fmt.Errorf("ppk: rsa d: %w", err)
	}
	pr, err := p.mpint()
	if err != nil {
		return nil, fmt.Errorf("ppk: rsa p: %w", err)
	}
	q, err := p.mpint()
	if err != nil {
		return nil, fmt.Errorf("ppk: rsa q: %w", err)
	}
	if !e.IsInt64() || e.Int64() < 3 {
		return nil, fmt.Errorf("ppk: rsa public exponent %s is not usable", e)
	}
	key := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{N: n, E: int(e.Int64())},
		D:         d,
		Primes:    []*big.Int{pr, q},
	}
	// Validate catches a wrong-passphrase decryption with arithmetic wording
	// before the public-half comparison gets a chance to say something vaguer.
	if err := key.Validate(); err != nil {
		return nil, fmt.Errorf("ppk: rsa key does not validate: %w", err)
	}
	key.Precompute()
	return key, nil
}

func (k *ppkKey) ed25519Key(priv []byte) (ed25519.PrivateKey, error) {
	r := &blobReader{b: priv}
	seed, err := r.mpint()
	if err != nil {
		return nil, fmt.Errorf("ppk: ed25519 seed: %w", err)
	}
	// PuTTY stores the seed as a number, so a seed whose high bit is set arrives
	// with one leading zero byte to keep it positive. Nothing else is a seed.
	b := seed.Bytes()
	if len(b) == ed25519.SeedSize+1 && b[0] == 0 {
		b = b[1:]
	}
	if len(b) != ed25519.SeedSize {
		return nil, fmt.Errorf("ppk: ed25519 seed is %d bytes, want %d", len(b), ed25519.SeedSize)
	}
	return ed25519.NewKeyFromSeed(b), nil
}

func (k *ppkKey) ecdsaKey(algo string, priv []byte) (*ecdsa.PrivateKey, error) {
	curve := ppkCurve(algo)
	if curve == nil {
		return nil, fmt.Errorf("ppk: unsupported curve in %q", algo)
	}
	r := &blobReader{b: priv}
	d, err := r.mpint()
	if err != nil {
		return nil, fmt.Errorf("ppk: ecdsa private value: %w", err)
	}
	if d.Sign() <= 0 {
		return nil, errors.New("ppk: ecdsa private value is not positive")
	}
	// The scalar must fit the curve. Going over the order is what a blob
	// decrypted under a wrong passphrase tends to produce, so it is reported
	// here rather than deep inside the curve arithmetic.
	if bits := curve.Params().BitSize; d.BitLen() > bits {
		return nil, fmt.Errorf("ppk: ecdsa private value is %d bits, too large for %s (%d bits)", d.BitLen(), algo, bits)
	}
	// The public point is derived from d, never copied from the file: taking it
	// from the file would make the public-half comparison pass for any
	// passphrase, which is the check that matters for an encrypted key.
	key := &ecdsa.PrivateKey{}
	key.PublicKey.Curve = curve
	key.D = d
	key.PublicKey.X, key.PublicKey.Y = curve.ScalarBaseMult(d.Bytes())
	return key, nil
}

// ppkCurve maps the algorithm name in the file header to its curve.
func ppkCurve(algo string) elliptic.Curve {
	switch algo {
	case "ecdsa-sha2-nistp256":
		return elliptic.P256()
	case "ecdsa-sha2-nistp384":
		return elliptic.P384()
	case "ecdsa-sha2-nistp521":
		return elliptic.P521()
	}
	return nil
}

// blobReader walks the SSH wire encoding used inside the two base64 blobs: a
// string or mpint is a uint32 length followed by that many bytes.
type blobReader struct {
	b   []byte
	err error
}

func (r *blobReader) str() ([]byte, error) {
	if r.err != nil {
		return nil, r.err
	}
	if len(r.b) < 4 {
		r.err = errors.New("blob is shorter than its length prefix")
		return nil, r.err
	}
	n := binary.BigEndian.Uint32(r.b)
	// uint32 n can far exceed what is left, and int(n) goes negative on a
	// 32-bit build: compare in uint64 against the remaining byte count.
	if uint64(n) > uint64(len(r.b)-4) {
		r.err = fmt.Errorf("blob field claims %d bytes, only %d remain", n, len(r.b)-4)
		return nil, r.err
	}
	s := r.b[4 : 4+n]
	r.b = r.b[4+n:]
	return s, nil
}

// mpint reads a positive SSH multiple-precision integer. A value with the sign
// bit set is negative, which no component of a key in this format ever is, so it
// means corruption or a hostile file and is rejected rather than mis-read.
func (r *blobReader) mpint() (*big.Int, error) {
	b, err := r.str()
	if err != nil {
		return nil, err
	}
	if len(b) == 0 {
		return new(big.Int), nil
	}
	if b[0]&0x80 != 0 {
		return nil, errors.New("blob contains a negative number")
	}
	return new(big.Int).SetBytes(b), nil
}
