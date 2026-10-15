package console_test

import (
	"bufio"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/ricevanta/ricevanta/server/internal/transport/console"
)

// FuzzPath sends arbitrary request targets through the root handler. No
// response is a redirect, every response carries the header set, a body is
// always bytes the tree holds in memory or a problem document, and a target
// with a dot, dot-dot or empty segment is never served.
func FuzzPath(f *testing.F) {
	for _, s := range []string{
		"/", "/a/../b", "/..", "/./x", "//x", "/a%2Fb", "/a%2fb", "/a%00b", "/a%5Cb", "/%2e%2e/b",
		"/assets/index-Bx1a2b3c.js", "/assets/index-Bx1a2b3c.js.br", "/assets/../assets/index-Bx1a2b3c.js",
		"/brand/favicon.ico", "/healthz", "/readyz", "/api/v1/x", "*", "/" + strings.Repeat("a", 1024),
		"http://x/a/../b", "/devices/42?x=1", "/a\\b",
	} {
		f.Add(s, "text/html")
	}
	h := newHandlerTB(f)
	files := map[string]bool{}
	m, _ := fixture(f)
	for _, file := range m {
		files[string(file.Data)] = true
	}
	f.Fuzz(func(t *testing.T, target, accept string) {
		r, err := http.ReadRequest(bufio.NewReader(strings.NewReader("GET " + target + " HTTP/1.1\r\nHost: x\r\nAccept: " + accept + "\r\n\r\n")))
		if err != nil {
			return
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code >= 300 && w.Code < 400 && w.Code != http.StatusNotModified {
			t.Fatalf("%q: redirect %d", target, w.Code)
		}
		if w.Header().Get("Content-Security-Policy") != console.CSP || w.Header().Get("Location") != "" {
			t.Fatalf("%q: headers %v", target, w.Header())
		}
		switch w.Code {
		case 200:
			if !files[w.Body.String()] && !strings.HasPrefix(w.Body.String(), `{"status":`) {
				t.Fatalf("%q: body not from the tree", target)
			}
		case 404, 405:
		default:
			t.Fatalf("%q: status %d", target, w.Code)
		}
		escaped := r.URL.EscapedPath()
		if decoded, err := url.PathUnescape(escaped); err == nil && strings.HasPrefix(decoded, "/") && decoded != "/" {
			for _, seg := range strings.Split(decoded[1:], "/") {
				if (seg == "" || seg == "." || seg == "..") && w.Code == 200 {
					t.Fatalf("%q: served a path with segment %q", target, seg)
				}
			}
		}
		if len(escaped) > 1024 && w.Code == 200 {
			t.Fatalf("served a %d-byte path", len(escaped))
		}
	})
}

func newHandlerTB(tb testing.TB) http.Handler {
	tb.Helper()
	m, manifest := fixture(tb)
	tree, err := console.Verify(m, manifest, devIdentity)
	if err != nil {
		tb.Fatal(err)
	}
	return console.NewHandler(tree, stubHealth(`{"status":"ok"}`), stubHealth(`{"status":"ready"}`))
}

// weight is an independent reading of RFC 9110 section 12.5.3 for one coding.
func weight(header, coding string) float64 {
	listed, star := -1.0, -1.0
	for _, part := range strings.Split(header, ",") {
		fields := strings.Split(part, ";")
		name := strings.ToLower(strings.TrimSpace(fields[0]))
		if name == "x-gzip" {
			name = "gzip"
		}
		q := 1.0
		for _, p := range fields[1:] {
			k, v, ok := strings.Cut(strings.TrimSpace(p), "=")
			if ok && strings.EqualFold(strings.TrimSpace(k), "q") {
				x, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
				if err != nil || x < 0 || x > 1 || !validQ(strings.TrimSpace(v)) {
					x = 0
				}
				q = x
			}
		}
		if name == coding && listed < 0 {
			listed = q
		}
		if name == "*" && star < 0 {
			star = q
		}
	}
	if listed >= 0 {
		return listed
	}
	if star >= 0 {
		return star
	}
	return 0
}

func validQ(v string) bool {
	if v == "1" || v == "0" {
		return true
	}
	if strings.HasPrefix(v, "1.") {
		return len(v) <= 5 && strings.Trim(v[2:], "0") == ""
	}
	if strings.HasPrefix(v, "0.") {
		d := v[2:]
		return len(d) <= 3 && strings.Trim(d, "0123456789") == ""
	}
	return false
}

// FuzzAcceptEncoding compares the negotiation with the oracle above: br is
// chosen only with a positive weight at least gzip's, gzip only with a
// positive weight above br's, and identity only when neither is acceptable.
func FuzzAcceptEncoding(f *testing.F) {
	for _, s := range []string{
		"br", "gzip", "br;q=0", "br;q=0, gzip", "*;q=0", "*", "*;q=0.5, br;q=0", "identity", "x-gzip",
		"br;q=1.5", "gzip;q=0.001, br;q=0.001", "gzip ; q=1 , br ; q=0.9", "br;q=0.0001", "br;q=", ",,,",
		"br;q=0, br", "BR;Q=0.5, GZIP;Q=0.6", "br;level=1;q=0.2",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, header string) {
		got := console.NegotiateEncoding(header)
		br, gz := weight(header, "br"), weight(header, "gzip")
		var want string
		switch {
		case br > 0 && br >= gz:
			want = "br"
		case gz > 0:
			want = "gzip"
		}
		if got != want {
			t.Fatalf("%q: got %q, want %q (br %v, gzip %v)", header, got, want, br, gz)
		}
	})
}
