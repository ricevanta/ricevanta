package console

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Write-progress bound of spec section 4: a write deadline 10 s ahead,
// moved forward after each 16 KiB written.
const (
	writeProgress = 10 * time.Second
	writeChunk    = 16 << 10
	maxPathBytes  = 1024
)

// reserved lists the prefixes of console design section 10 that never fall
// back to index.html. A path is under one when it equals the prefix or
// continues it with a slash.
var reserved = []string{"/api", "/agent", "/ext", "/assets", "/brand", "/mdm", "/scep", "/acme", "/metrics", "/healthz", "/readyz"}

func under(p, prefix string) bool {
	return p == prefix || strings.HasPrefix(p, prefix+"/")
}

func isReserved(p string) bool {
	for _, r := range reserved {
		if under(p, r) {
			return true
		}
	}
	return false
}

// isConsolePath reports whether p belongs to the console rather than to a
// reserved family without a handler in this build.
func isConsolePath(p string) bool {
	return !isReserved(p) || under(p, "/assets") || under(p, "/brand")
}

// SetHeaders writes the foundation header set of console foundation
// section 4, adding HSTS on TLS listeners.
func SetHeaders(h http.Header, tlsOn bool) {
	h.Set("Content-Security-Policy", CSP)
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), usb=(), payment=()")
	if tlsOn {
		h.Set("Strict-Transport-Security", "max-age=31536000")
	}
}

// cleanPath checks the escaped request path and decodes it exactly once. It
// refuses a path over 1,024 bytes, a percent-encoded slash, NUL, a
// backslash, and an empty, "." or ".." segment.
func cleanPath(escaped string) (string, bool) {
	if len(escaped) > maxPathBytes || !strings.HasPrefix(escaped, "/") {
		return "", false
	}
	if strings.Contains(strings.ToUpper(escaped), "%2F") {
		return "", false
	}
	decoded, err := url.PathUnescape(escaped)
	if err != nil || strings.ContainsAny(decoded, "\x00\\") {
		return "", false
	}
	if decoded == "/" {
		return decoded, true
	}
	for _, seg := range strings.Split(decoded[1:], "/") {
		if seg == "" || seg == "." || seg == ".." {
			return "", false
		}
	}
	return decoded, true
}

type handler struct {
	tree            *Tree
	healthz, readyz http.Handler
}

// NewHandler returns the api listener's single root handler. tree is nil
// when the console is disabled. No http.ServeMux sits in front, so no
// request is ever redirected.
func NewHandler(tree *Tree, healthz, readyz http.Handler) http.Handler {
	return &handler{tree: tree, healthz: healthz, readyz: readyz}
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	SetHeaders(w.Header(), r.TLS != nil)
	// Content is refused before the method or path is examined.
	if r.ContentLength != 0 {
		RefuseContent(w, r)
		return
	}
	p, ok := cleanPath(r.URL.EscapedPath())
	switch {
	case ok && p == "/healthz":
		h.healthz.ServeHTTP(w, r)
		return
	case ok && p == "/readyz":
		h.readyz.ServeHTTP(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		if ok && !isConsolePath(p) {
			Problem(w, r, http.StatusNotFound)
			return
		}
		w.Header().Set("Allow", "GET, HEAD")
		Problem(w, r, http.StatusMethodNotAllowed)
		return
	}
	if !ok || h.tree == nil {
		Problem(w, r, http.StatusNotFound)
		return
	}
	if under(p, "/assets") || under(p, "/brand") {
		if res, found := h.tree.resources[p[1:]]; found {
			serve(w, r, res, "Accept-Encoding")
			return
		}
		Problem(w, r, http.StatusNotFound)
		return
	}
	if isReserved(p) || !acceptsHTML(r.Header.Values("Accept")) {
		Problem(w, r, http.StatusNotFound)
		return
	}
	serve(w, r, h.tree.index, "Accept, Accept-Encoding")
}

func serve(w http.ResponseWriter, r *http.Request, res *resource, vary string) {
	rep, coding := &res.identity, choose(strings.Join(r.Header.Values("Accept-Encoding"), ","), res.br != nil, res.gz != nil)
	switch coding {
	case "br":
		rep = res.br
	case "gzip":
		rep = res.gz
	}
	hdr := w.Header()
	hdr.Set("Content-Type", res.contentType)
	hdr.Set("Cache-Control", res.cache)
	hdr.Set("ETag", rep.etag)
	hdr.Set("Vary", vary)
	if coding != "" {
		hdr.Set("Content-Encoding", coding)
	}
	hdr.Set("Content-Length", strconv.Itoa(len(rep.body)))
	if noneMatch(r.Header.Values("If-None-Match"), rep.etag) {
		Write(w, r, http.StatusNotModified, nil)
		return
	}
	Write(w, r, http.StatusOK, rep.body)
}

// noneMatch reports whether an If-None-Match field matches tag under the
// weak comparison of RFC 9110 section 13.1.2.
func noneMatch(values []string, tag string) bool {
	s := strings.Join(values, ",")
	for {
		s = strings.TrimLeft(s, " \t,")
		if s == "" {
			return false
		}
		if s[0] == '*' {
			return true
		}
		s = strings.TrimPrefix(s, "W/")
		if s == "" || s[0] != '"' {
			return false
		}
		end := strings.IndexByte(s[1:], '"')
		if end < 0 {
			return false
		}
		if s[:end+2] == tag {
			return true
		}
		s = s[end+2:]
	}
}

// RefuseContent answers a request that declares content with 413 and
// Connection: close after expiring the read deadline, so net/http's close
// of the unread body fails at once instead of reading under no deadline.
func RefuseContent(w http.ResponseWriter, r *http.Request) {
	// An unsupported writer (a test recorder) has no connection to bound.
	_ = http.NewResponseController(w).SetReadDeadline(time.Now())
	w.Header().Set("Connection", "close")
	Problem(w, r, http.StatusRequestEntityTooLarge)
}

// Problem writes an RFC 9457 problem document for status.
func Problem(w http.ResponseWriter, r *http.Request, status int) {
	body := []byte(`{"status":` + strconv.Itoa(status) + `,"title":` + strconv.Quote(http.StatusText(status)) + `,"type":"about:blank"}`)
	hdr := w.Header()
	hdr.Set("Content-Type", "application/problem+json")
	hdr.Set("Cache-Control", "no-store")
	hdr.Set("Content-Length", strconv.Itoa(len(body)))
	Write(w, r, status, body)
}

// Write sends status and body under the write-progress deadline: 10 s ahead
// before the first write and moved 10 s ahead after each 16 KiB. HEAD and
// 304 responses send no body.
func Write(w http.ResponseWriter, r *http.Request, status int, body []byte) {
	rc := http.NewResponseController(w)
	extend := func() { _ = rc.SetWriteDeadline(time.Now().Add(writeProgress)) }
	extend()
	w.WriteHeader(status)
	if r.Method == http.MethodHead || status == http.StatusNotModified {
		return
	}
	for len(body) > 0 {
		n := min(len(body), writeChunk)
		if _, err := w.Write(body[:n]); err != nil {
			return
		}
		body = body[n:]
		extend()
	}
}
