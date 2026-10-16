//go:build unix

package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"syscall"
)

// openRegular opens path for reading, following symbolic links, without
// blocking on a FIFO or device, and requires fstat of the opened file to
// report a regular file.
func openRegular(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
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

// keyStat is the part of fstat the key-file rule judges.
type keyStat struct {
	uid, gid   uint32
	perm       fs.FileMode
	special    bool // setuid, setgid or sticky
	notRegular bool
}

// procIdentity is the effective user, effective group and supplementary
// groups of the process.
type procIdentity struct {
	euid, egid uint32
	groups     []uint32
}

func currentIdentity() (procIdentity, error) {
	groups, err := os.Getgroups()
	if err != nil {
		return procIdentity{}, err
	}
	id := procIdentity{euid: uint32(os.Geteuid()), egid: uint32(os.Getegid())}
	for _, g := range groups {
		id.groups = append(id.groups, uint32(g))
	}
	return id, nil
}

// checkKeyStat applies spec section 3: a regular file owned by root or the
// effective user, with permission bits exactly 0400, 0600, 0440 or 0640, and
// the group-readable modes only when the file's group is the effective group
// or a supplementary group of the process.
func checkKeyStat(st keyStat, id procIdentity) error {
	if st.notRegular {
		return errors.New("is not a regular file")
	}
	if st.uid != 0 && st.uid != id.euid {
		return errors.New("must be owned by root or the server's effective user")
	}
	if st.special {
		return errors.New("must not have setuid, setgid or sticky bits")
	}
	switch st.perm {
	case 0o400, 0o600:
		return nil
	case 0o440, 0o640:
		if st.gid == id.egid {
			return nil
		}
		for _, g := range id.groups {
			if g == st.gid {
				return nil
			}
		}
		return errors.New("is group-readable but its group is not a group of the server process")
	default:
		return fmt.Errorf("has mode %04o; allowed modes are 0400, 0600, 0440 and 0640", uint32(st.perm))
	}
}

// ReadKeyFile opens the private key at path once, following symbolic links
// such as a Kubernetes Secret volume's ..data chain, judges fstat of the
// opened file with the key-file rule and reads at most 1 MiB from the same
// descriptor.
func ReadKeyFile(path string) ([]byte, error) {
	reject := func(reason string) error {
		return &Error{Code: CodeKeyFileRejected, Field: "listen.api.tls.key_file", Reason: reason}
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, reject("cannot open: " + sanitizePathError(err).Error())
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, reject("cannot stat the opened file")
	}
	sys, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, reject("owner of the opened file is unavailable")
	}
	mode := fi.Mode()
	st := keyStat{
		uid:        uint32(sys.Uid),
		gid:        uint32(sys.Gid),
		perm:       mode.Perm(),
		special:    mode&(fs.ModeSetuid|fs.ModeSetgid|fs.ModeSticky) != 0,
		notRegular: !mode.IsRegular(),
	}
	id, err := currentIdentity()
	if err != nil {
		return nil, reject("cannot read the process groups")
	}
	if err := checkKeyStat(st, id); err != nil {
		return nil, reject(err.Error())
	}
	data, err := readBounded(f, maxPEMBytes)
	if err != nil {
		return nil, reject("cannot read: " + err.Error())
	}
	return data, nil
}
