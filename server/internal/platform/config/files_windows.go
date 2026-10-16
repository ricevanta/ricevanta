//go:build windows

package config

import (
	"errors"
	"os"
)

// openRegular opens path for reading and requires a regular file.
func openRegular(path string) (*os.File, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		f.Close()
		return nil, errors.New("not a regular file")
	}
	return f, nil
}

// ReadKeyFile refuses every key on Windows. The key-file rule judges POSIX
// ownership and permission bits, which Windows does not have; Go reports
// only a read-only attribute there, so the rule cannot be evaluated and the
// server fails closed. Windows builds are test conveniences, not a supported
// deployment (spec section 1); use tls.mode none on loopback for local tests.
func ReadKeyFile(path string) ([]byte, error) {
	return nil, &Error{Code: CodeKeyFileRejected, Field: "listen.api.tls.key_file",
		Reason: "key file ownership and permissions cannot be verified on Windows"}
}
