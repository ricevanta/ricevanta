package manifest

import (
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

func metadata(document map[string]any) error {
	m := document["metadata"].(map[string]any)
	p := licenseParser{text: m["license"].(string)}
	if !p.expression(0) || p.position != len(p.text) {
		return ErrLicense
	}
	for _, key := range []string{"source", "homepage"} {
		if s, ok := m[key].(string); ok && !validURL(s) {
			return ErrURL
		}
	}
	return nil
}

type licenseParser struct {
	text     string
	position int
}

func (p *licenseParser) consume(s string) bool {
	if !strings.HasPrefix(p.text[p.position:], s) {
		return false
	}
	p.position += len(s)
	return true
}
func identifierByte(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.'
}
func (p *licenseParser) token() string {
	start := p.position
	for p.position < len(p.text) && identifierByte(p.text[p.position]) {
		p.position++
	}
	return p.text[start:p.position]
}
func ordinary(s string) bool {
	if s == "" || strings.HasPrefix(s, "LicenseRef-") || strings.HasPrefix(s, "DocumentRef-") {
		return false
	}
	switch s {
	case "AND", "OR", "WITH", "NONE", "NOASSERTION":
		return false
	}
	return true
}
func (p *licenseParser) simple() (bool, bool) {
	s := p.token()
	if strings.HasPrefix(s, "DocumentRef-") {
		if len(s) == len("DocumentRef-") || !p.consume(":") {
			return false, false
		}
		s = p.token()
		return strings.HasPrefix(s, "LicenseRef-") && len(s) > len("LicenseRef-"), true
	}
	if strings.HasPrefix(s, "LicenseRef-") {
		return len(s) > len("LicenseRef-"), true
	}
	if !ordinary(s) {
		return false, false
	}
	p.consume("+")
	return true, false
}
func (p *licenseParser) factor(depth int) bool {
	if p.consume("(") {
		if depth == 8 || !p.expression(depth+1) || !p.consume(")") {
			return false
		}
		return true
	}
	ok, reference := p.simple()
	if !ok {
		return false
	}
	if !reference && p.consume(" WITH ") {
		return ordinary(p.token())
	}
	return true
}
func (p *licenseParser) term(depth int) bool {
	if !p.factor(depth) {
		return false
	}
	for p.consume(" AND ") {
		if !p.factor(depth) {
			return false
		}
	}
	return true
}
func (p *licenseParser) expression(depth int) bool {
	if !p.term(depth) {
		return false
	}
	for p.consume(" OR ") {
		if !p.term(depth) {
			return false
		}
	}
	return true
}
func hexByte(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'A' && c <= 'F' || c >= 'a' && c <= 'f'
}
func validURL(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '%' {
			if i+2 >= len(s) || !hexByte(s[i+1]) || !hexByte(s[i+2]) {
				return false
			}
			i += 2
		}
	}
	u, e := url.Parse(s)
	if e != nil {
		return false
	}
	host := u.Hostname()
	if len(host) > 253 {
		return false
	}
	if _, e := netip.ParseAddr(host); e == nil {
		return false
	}
	if port := u.Port(); port != "" {
		n, e := strconv.ParseUint(port, 10, 16)
		if e != nil || n == 0 {
			return false
		}
	}
	return true
}
