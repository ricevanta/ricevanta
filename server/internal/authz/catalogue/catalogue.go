package catalogue

import (
	"bytes"
	"sort"
)

// Permission describes metadata, not a grant or an authorization decision.
type Permission struct {
	Name, Owner, Scope, Protection, Approval, Rule, Grant, Status string
	Introduced, RetiredIn                                         uint32
	Uses                                                          []string
	Source, Note                                                  string
}

type Catalogue struct {
	revision uint32
	entries  []Permission
	data     []byte
}

// Lookup returns detached metadata for an exact active name.
func (c *Catalogue) Lookup(name string) (Permission, error) {
	if err := ValidateName(name); err != nil {
		return Permission{}, err
	}
	if c == nil || c.revision == 0 {
		return Permission{}, ErrUnavailable
	}
	i := sort.Search(len(c.entries), func(i int) bool { return c.entries[i].Name >= name })
	if i == len(c.entries) || c.entries[i].Name != name {
		return Permission{}, ErrUnknownPermission
	}
	if c.entries[i].Status == "retired" {
		return Permission{}, ErrRetiredPermission
	}
	return copyPermission(c.entries[i]), nil
}

// Entries returns detached entries, including permanent tombstones.
func (c *Catalogue) Entries() []Permission {
	if c == nil || c.revision == 0 {
		return nil
	}
	out := make([]Permission, len(c.entries))
	for i, p := range c.entries {
		out[i] = copyPermission(p)
	}
	return out
}

// Revision returns zero when the catalogue is unavailable.
func (c *Catalogue) Revision() uint32 {
	if c == nil {
		return 0
	}
	return c.revision
}

// JSON returns a detached copy of the exact accepted bytes.
func (c *Catalogue) JSON() []byte {
	if c == nil || c.revision == 0 {
		return nil
	}
	return bytes.Clone(c.data)
}
func copyPermission(p Permission) Permission { p.Uses = append([]string(nil), p.Uses...); return p }
