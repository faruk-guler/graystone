package sshclient

import (
	"crypto/x509"
	"errors"
	"fmt"

	"golang.org/x/crypto/ssh"
)

// ErrWrongPassphrase marks the one key failure that is worth asking about again:
// the key file is fine, the passphrase typed did not open it. Every other key
// problem (unreadable file, unknown format, unsupported algorithm) is a dead end
// that typing the same thing twice cannot change, and is reported as such.
var ErrWrongPassphrase = errors.New("wrong key passphrase")

// KeyFileError names the file a key could not be loaded from, so the terminal
// can point at the broken profile entry instead of an anonymous parse failure.
type KeyFileError struct {
	Path string
	Err  error
}

func (e *KeyFileError) Error() string {
	return fmt.Sprintf("sshclient: cannot use key %s: %v", e.Path, e.Err)
}

func (e *KeyFileError) Unwrap() error { return e.Err }

// loadPrivateKey turns a private key file's bytes plus a passphrase into a
// signer. It reads what an OpenSSH client reads (PEM and the newer
// "openssh-key-v1" format) and, because PuTTY users are the audience Graystone is
// built for, PuTTY's own .ppk format in both its v2 and v3 flavours.
//
// Failures are wrapped in KeyFileError, and the subset that a better passphrase
// could fix also match ErrWrongPassphrase - which is what lets the connect flow
// re-prompt in place instead of dropping a dead terminal on screen.
func loadPrivateKey(data []byte, passphrase, path string) (ssh.Signer, error) {
	if isPPK(data) {
		signer, err := parsePPK(data, passphrase)
		if err != nil {
			return nil, &KeyFileError{Path: path, Err: err}
		}
		return signer, nil
	}

	var signer ssh.Signer
	var err error
	if passphrase == "" {
		signer, err = ssh.ParsePrivateKey(data)
		// A protected key reached without a passphrase is exactly the case the
		// prompt exists for, so it is reported like a mistyped one.
		var missing *ssh.PassphraseMissingError
		if errors.As(err, &missing) {
			err = fmt.Errorf("%w: the key is passphrase protected, no passphrase was given", ErrWrongPassphrase)
		}
	} else {
		signer, err = ssh.ParsePrivateKeyWithPassphrase(data, []byte(passphrase))
		if errors.Is(err, x509.IncorrectPasswordError) {
			err = fmt.Errorf("%w: %v", ErrWrongPassphrase, err)
		}
	}
	if err != nil {
		return nil, &KeyFileError{Path: path, Err: err}
	}
	return signer, nil
}
