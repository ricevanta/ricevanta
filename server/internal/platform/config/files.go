package config

import (
	"errors"
	"io"
	"io/fs"
	"os"
)

// maxPEMBytes bounds a certificate or key file.
const maxPEMBytes = 1 << 20

// sanitizePathError reduces a file error to its cause, without the path.
func sanitizePathError(err error) error {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	return err
}

func readBounded(f *os.File, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("file exceeds the size bound")
	}
	return data, nil
}

// ReadCertificateFile reads the PEM certificate chain at path, which must be
// a regular file of at most 1 MiB. Symbolic links are followed.
func ReadCertificateFile(path string) ([]byte, error) {
	f, err := openRegular(path)
	if err != nil {
		return nil, &Error{Code: CodeCertificateFileRejected, Reason: "cannot open: " + sanitizePathError(err).Error()}
	}
	defer f.Close()
	data, err := readBounded(f, maxPEMBytes)
	if err != nil {
		return nil, &Error{Code: CodeCertificateFileRejected, Reason: "cannot read: " + err.Error()}
	}
	return data, nil
}
