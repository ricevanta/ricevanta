package console_test

import (
	"bufio"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ricevanta/ricevanta/server/internal/transport/console"
)

// baseHeaders is console foundation section 4's header set.
func baseHeaders(t *testing.T) map[string]string {
	t.Helper()
	data, err := os.ReadFile("../../../../console/security/csp.txt")
	if err != nil {
		t.Fatal(err)
	}
	return map[string]string{
		"Content-Security-Policy":      strings.TrimSuffix(string(data), "\n"),
		"Cross-Origin-Opener-Policy":   "same-origin",
		"Cross-Origin-Resource-Policy": "same-origin",
		"Referrer-Policy":              "no-referrer",
		"X-Content-Type-Options":       "nosniff",
		"X-Frame-Options":              "DENY",
		"Permissions-Policy":           "camera=(), microphone=(), geolocation=(), usb=(), payment=()",
	}
}

// stubHealth answers like a health handler so routing can be observed.
type stubHealth string

func (s stubHealth) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	io.WriteString(w, string(s))
}

func newHandler(t *testing.T) http.Handler {
	t.Helper()
	m, manifest := fixture(t)
	tree, err := console.Verify(m, manifest, devIdentity)
	if err != nil {
		t.Fatal(err)
	}
	return console.NewHandler(tree, stubHealth(`{"status":"ok"}`), stubHealth(`{"status":"ready"}`))
}

type req struct {
	method, target string
	header         map[string]string
	tls            bool
}

func do(t *testing.T, h http.Handler, q req) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(q.method, q.target, nil)
	for k, v := range q.header {
		r.Header.Set(k, v)
	}
	if !q.tls {
		r.TLS = nil
	} else if r.TLS == nil {
		r.TLS = &tls.ConnectionState{}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code >= 300 && w.Code < 400 && w.Code != http.StatusNotModified {
		t.Fatalf("%s %s answered %d", q.method, q.target, w.Code)
	}
	return w
}

func checkBase(t *testing.T, w *httptest.ResponseRecorder, tlsOn bool) {
	t.Helper()
	for k, v := range baseHeaders(t) {
		if got := w.Result().Header.Values(k); len(got) != 1 || got[0] != v {
			t.Errorf("%s = %q, want exactly %q", k, got, v)
		}
	}
	hsts := w.Result().Header.Values("Strict-Transport-Security")
	if tlsOn && (len(hsts) != 1 || hsts[0] != "max-age=31536000") {
		t.Errorf("HSTS on TLS = %q", hsts)
	}
	if !tlsOn && len(hsts) != 0 {
		t.Errorf("HSTS on plaintext = %q", hsts)
	}
	for _, k := range []string{"Last-Modified", "Accept-Ranges", "Location"} {
		if v := w.Result().Header.Get(k); v != "" {
			t.Errorf("%s = %q", k, v)
		}
	}
}

func digest(t *testing.T, p string) string {
	t.Helper()
	data, err := os.ReadFile("testdata/dist/" + p)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	return `"` + hex.EncodeToString(sum[:]) + `"`
}

func body(t *testing.T, p string) string {
	t.Helper()
	data, err := os.ReadFile("testdata/dist/" + p)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func checkProblem(t *testing.T, w *httptest.ResponseRecorder, status int) {
	t.Helper()
	if w.Code != status {
		t.Fatalf("status %d, want %d", w.Code, status)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Fatalf("Content-Type %q", ct)
	}
	var p map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
		t.Fatalf("problem body %q: %v", w.Body.Bytes(), err)
	}
	if p["status"] != float64(status) || p["type"] != "about:blank" || p["title"] != http.StatusText(status) {
		t.Fatalf("problem %v", p)
	}
}

const jsAsset = "assets/index-Bx1a2b3c.js"

func TestHeaderSetOnEveryResponse(t *testing.T) {
	h := newHandler(t)
	for _, q := range []req{
		{method: "GET", target: "/"},
		{method: "GET", target: "/" + jsAsset},
		{method: "GET", target: "/" + jsAsset, tls: true},
		{method: "GET", target: "/assets/missing.js"},
		{method: "POST", target: "/"},
		{method: "GET", target: "/a/../b"},
		{method: "GET", target: "/healthz"},
		{method: "HEAD", target: "/brand/favicon.ico", tls: true},
		{method: "GET", target: "/devices/42", header: map[string]string{"Accept": "application/json"}},
		{method: "GET", target: "/" + jsAsset, header: map[string]string{"If-None-Match": digest(t, jsAsset)}},
	} {
		t.Run(q.method+" "+q.target, func(t *testing.T) {
			checkBase(t, do(t, h, q), q.tls)
		})
	}
}

func TestImmutableAsset(t *testing.T) {
	h := newHandler(t)
	for _, tlsOn := range []bool{false, true} {
		w := do(t, h, req{method: "GET", target: "/" + jsAsset, tls: tlsOn})
		if w.Code != 200 || w.Body.String() != body(t, jsAsset) {
			t.Fatalf("status %d body %q", w.Code, w.Body.String())
		}
		want := map[string]string{
			"Content-Type":   "text/javascript; charset=utf-8",
			"Cache-Control":  "public, max-age=31536000, immutable",
			"ETag":           digest(t, jsAsset),
			"Vary":           "Accept-Encoding",
			"Content-Length": "34",
		}
		for k, v := range want {
			if got := w.Header().Get(k); got != v {
				t.Errorf("%s = %q, want %q", k, got, v)
			}
		}
		if w.Header().Get("Content-Encoding") != "" {
			t.Errorf("identity response has Content-Encoding")
		}
		checkBase(t, w, tlsOn)
	}
	css := do(t, h, req{method: "GET", target: "/assets/index-Cx9y8z7w.css"})
	if css.Header().Get("Cache-Control") != "public, max-age=31536000, immutable" || css.Header().Get("Content-Type") != "text/css; charset=utf-8" {
		t.Fatalf("css headers %v", css.Header())
	}
}

func TestConditionalRequest(t *testing.T) {
	h := newHandler(t)
	full := do(t, h, req{method: "GET", target: "/" + jsAsset})
	for _, inm := range []string{digest(t, jsAsset), "W/" + digest(t, jsAsset), `"other", ` + digest(t, jsAsset), "*"} {
		w := do(t, h, req{method: "GET", target: "/" + jsAsset, header: map[string]string{"If-None-Match": inm}})
		if w.Code != http.StatusNotModified || w.Body.Len() != 0 {
			t.Fatalf("If-None-Match %s: status %d body %d", inm, w.Code, w.Body.Len())
		}
		for _, k := range []string{"ETag", "Cache-Control", "Vary"} {
			if w.Header().Get(k) != full.Header().Get(k) {
				t.Errorf("304 %s = %q, want %q", k, w.Header().Get(k), full.Header().Get(k))
			}
		}
	}
	w := do(t, h, req{method: "GET", target: "/" + jsAsset, header: map[string]string{"If-None-Match": `"different"`}})
	if w.Code != 200 {
		t.Fatalf("non-matching If-None-Match: %d", w.Code)
	}
}

func TestEncodingNegotiation(t *testing.T) {
	h := newHandler(t)
	cases := []struct {
		accept, encoding, file string
	}{
		{"br", "br", jsAsset + ".br"},
		{"gzip", "gzip", jsAsset + ".gz"},
		{"gzip, br", "br", jsAsset + ".br"},
		{"br;q=0.5, gzip;q=0.8", "gzip", jsAsset + ".gz"},
		{"br;q=0, gzip", "gzip", jsAsset + ".gz"},
		{"br;q=0", "", jsAsset},
		{"BR", "br", jsAsset + ".br"},
		{"*", "br", jsAsset + ".br"},
		{"*;q=0", "", jsAsset},
		{"*;q=0.5, br;q=0", "gzip", jsAsset + ".gz"},
		{"identity", "", jsAsset},
		{"deflate", "", jsAsset},
		{"x-gzip", "gzip", jsAsset + ".gz"},
		{"", "", jsAsset},
		{"br;q=1.5", "", jsAsset},
		{"gzip;q=0.001, br;q=0.001", "br", jsAsset + ".br"},
		{"gzip ; q=1 , br ; q=0.9", "gzip", jsAsset + ".gz"},
	}
	for _, c := range cases {
		t.Run(c.accept, func(t *testing.T) {
			hdr := map[string]string{}
			if c.accept != "" {
				hdr["Accept-Encoding"] = c.accept
			}
			w := do(t, h, req{method: "GET", target: "/" + jsAsset, header: hdr})
			if w.Code != 200 {
				t.Fatalf("status %d", w.Code)
			}
			if got := w.Header().Get("Content-Encoding"); got != c.encoding {
				t.Fatalf("Content-Encoding %q, want %q", got, c.encoding)
			}
			if w.Body.String() != body(t, c.file) {
				t.Fatalf("body %q, want %s", w.Body.String(), c.file)
			}
			if w.Header().Get("Vary") != "Accept-Encoding" {
				t.Fatalf("Vary %q", w.Header().Get("Vary"))
			}
			if w.Header().Get("Content-Type") != "text/javascript; charset=utf-8" {
				t.Fatalf("Content-Type %q", w.Header().Get("Content-Type"))
			}
			if w.Header().Get("Content-Length") != itoa(len(body(t, c.file))) {
				t.Fatalf("Content-Length %q", w.Header().Get("Content-Length"))
			}
			if w.Header().Get("ETag") != digest(t, c.file) {
				t.Fatalf("ETag %q, want the served representation's digest", w.Header().Get("ETag"))
			}
		})
	}
	// A coded ETag yields 304 only for a request that negotiates that coding.
	w := do(t, h, req{method: "GET", target: "/" + jsAsset, header: map[string]string{"Accept-Encoding": "br", "If-None-Match": digest(t, jsAsset+".br")}})
	if w.Code != http.StatusNotModified {
		t.Fatalf("br revalidation %d", w.Code)
	}
	w = do(t, h, req{method: "GET", target: "/" + jsAsset, header: map[string]string{"If-None-Match": digest(t, jsAsset+".br")}})
	if w.Code != 200 {
		t.Fatalf("identity request matched a br ETag: %d", w.Code)
	}
}

func itoa(i int) string {
	b, _ := json.Marshal(i)
	return string(b)
}

func TestSidecarsNotAddressable(t *testing.T) {
	h := newHandler(t)
	for _, p := range []string{jsAsset + ".br", jsAsset + ".gz", "assets/index-Cx9y8z7w.css.br"} {
		w := do(t, h, req{method: "GET", target: "/" + p, header: map[string]string{"Accept": "*/*", "Accept-Encoding": "br, gzip"}})
		checkProblem(t, w, 404)
	}
}

func TestUnlistedAssetNoCache(t *testing.T) {
	h := newHandler(t)
	for _, c := range []struct{ path, ctype string }{
		{"assets/unlisted.svg", "image/svg+xml; charset=utf-8"},
		{"assets/FONT-NOTICE.txt", "text/plain; charset=utf-8"},
	} {
		w := do(t, h, req{method: "GET", target: "/" + c.path})
		if w.Code != 200 || w.Header().Get("Cache-Control") != "no-cache" || w.Header().Get("Content-Type") != c.ctype ||
			w.Header().Get("ETag") != digest(t, c.path) || w.Body.String() != body(t, c.path) {
			t.Fatalf("%s: %d %v", c.path, w.Code, w.Header())
		}
	}
}

func TestBrand(t *testing.T) {
	h := newHandler(t)
	w := do(t, h, req{method: "GET", target: "/brand/favicon.ico"})
	if w.Code != 200 || w.Header().Get("Cache-Control") != "public, max-age=86400" || w.Header().Get("Content-Type") != "image/x-icon" ||
		w.Header().Get("ETag") != digest(t, "brand/favicon.ico") || w.Body.String() != body(t, "brand/favicon.ico") {
		t.Fatalf("brand: %d %v", w.Code, w.Header())
	}
}

func TestIndexFallback(t *testing.T) {
	h := newHandler(t)
	for _, q := range []req{
		{method: "GET", target: "/", header: map[string]string{"Accept": "text/html"}},
		{method: "GET", target: "/devices/42", header: map[string]string{"Accept": "text/html,application/xhtml+xml;q=0.9"}},
		{method: "GET", target: "/devices/42", header: map[string]string{"Accept": "*/*"}},
		{method: "GET", target: "/devices/42"},
		{method: "GET", target: "/index.html", header: map[string]string{"Accept": "text/html"}},
		{method: "GET", target: "/build-info.json", header: map[string]string{"Accept": "text/html"}},
		{method: "GET", target: "/devices/42?tab=x", header: map[string]string{"Accept": "text/*"}},
	} {
		w := do(t, h, q)
		if w.Code != 200 || w.Body.String() != body(t, "index.html") {
			t.Fatalf("%s %v: %d", q.target, q.header, w.Code)
		}
		if w.Header().Get("Cache-Control") != "no-cache" || w.Header().Get("Content-Type") != "text/html; charset=utf-8" ||
			w.Header().Get("ETag") != digest(t, "index.html") {
			t.Fatalf("%s: headers %v", q.target, w.Header())
		}
	}
	w := do(t, h, req{method: "GET", target: "/", header: map[string]string{"Accept": "text/html", "If-None-Match": digest(t, "index.html")}})
	if w.Code != http.StatusNotModified {
		t.Fatalf("index revalidation %d", w.Code)
	}
}

func TestNonHTMLClientGetsNoDocument(t *testing.T) {
	h := newHandler(t)
	for _, accept := range []string{"application/json", "text/html;q=0, */*", "image/png", "text/plain", "*/*;q=0"} {
		checkProblem(t, do(t, h, req{method: "GET", target: "/devices/42", header: map[string]string{"Accept": accept}}), 404)
	}
}

func TestReservedPrefixes(t *testing.T) {
	h := newHandler(t)
	for _, p := range []string{
		"/api/v1/devices", "/api", "/api/", "/agent/v1/checkin", "/ext/x", "/assets/missing.js", "/assets/",
		"/brand/missing.png", "/mdm/checkin", "/scep", "/scep/pkiclient.exe", "/acme/directory", "/metrics",
		"/metrics/x", "/healthz/x", "/readyz/x", "/assets/index.html", "/assets",
	} {
		w := do(t, h, req{method: "GET", target: p, header: map[string]string{"Accept": "text/html, */*"}})
		checkProblem(t, w, 404)
		checkBase(t, w, false)
	}
	// A path that merely starts with the same letters is not reserved.
	w := do(t, h, req{method: "GET", target: "/scepter", header: map[string]string{"Accept": "text/html"}})
	if w.Code != 200 {
		t.Fatalf("/scepter: %d", w.Code)
	}
}

func TestMethods(t *testing.T) {
	h := newHandler(t)
	for _, m := range []string{"POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE", "CONNECT-LIKE"} {
		w := do(t, h, req{method: m, target: "/"})
		checkProblem(t, w, 405)
		if w.Header().Get("Allow") != "GET, HEAD" {
			t.Fatalf("%s Allow %q", m, w.Header().Get("Allow"))
		}
	}
	w := do(t, h, req{method: "POST", target: "/" + jsAsset})
	checkProblem(t, w, 405)
	w = do(t, h, req{method: "POST", target: "/api/v1/devices"})
	checkProblem(t, w, 404)
}

func TestHeadMirrorsGet(t *testing.T) {
	h := newHandler(t)
	for _, q := range []req{
		{target: "/" + jsAsset, header: map[string]string{"Accept-Encoding": "br"}},
		{target: "/", header: map[string]string{"Accept": "text/html"}},
		{target: "/assets/missing.js"},
		{target: "/brand/favicon.ico"},
	} {
		q.method = "GET"
		g := do(t, h, q)
		q.method = "HEAD"
		hd := do(t, h, q)
		if hd.Code != g.Code || hd.Body.Len() != 0 {
			t.Fatalf("%s: HEAD %d body %d, GET %d", q.target, hd.Code, hd.Body.Len(), g.Code)
		}
		for k := range g.Header() {
			if hd.Header().Get(k) != g.Header().Get(k) {
				t.Errorf("%s: HEAD %s = %q, GET %q", q.target, k, hd.Header().Get(k), g.Header().Get(k))
			}
		}
	}
}

func TestBadPaths(t *testing.T) {
	h := newHandler(t)
	long := "/" + strings.Repeat("a", 1024)
	for _, p := range []string{
		"/a/../b", "/..", "/assets/../index.html", "/./x", "/assets/./" + strings.TrimPrefix(jsAsset, "assets/"),
		"//x", "/assets//index-Bx1a2b3c.js", "/devices/", "/a%2Fb", "/a%2fb", "/assets%2Findex-Bx1a2b3c.js",
		"/a%00b", "/a%5Cb", "/%2e%2e/b", "/a/%2e%2e/b", "/%2e", "/a/%2E%2E", long, "/a\\b", "http://x/a/../b",
	} {
		rawStatus(t, h, "GET "+p+" HTTP/1.1\r\nHost: x\r\nAccept: text/html\r\n\r\n", 404)
	}
	if len("/"+strings.Repeat("a", 1023)) != 1024 {
		t.Fatal("length arithmetic")
	}
	w := do(t, h, req{method: "GET", target: "/" + strings.Repeat("a", 1023), header: map[string]string{"Accept": "text/html"}})
	if w.Code != 200 {
		t.Fatalf("1,024-byte path: %d", w.Code)
	}
}

// rawStatus sends a raw request to h over a loopback server with Go's
// built-in OPTIONS handler disabled and requires status code want.
func rawStatus(t *testing.T, h http.Handler, raw string, want int) *http.Response {
	t.Helper()
	srv := httptest.NewUnstartedServer(h)
	srv.Config.DisableGeneralOptionsHandler = true
	srv.Start()
	defer srv.Close()
	c, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(c, raw); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != want {
		t.Fatalf("%q: status %d, want %d", raw, resp.StatusCode, want)
	}
	return resp
}

func TestOptionsStarReachesHandler(t *testing.T) {
	h := newHandler(t)
	resp := rawStatus(t, h, "OPTIONS * HTTP/1.1\r\nHost: x\r\n\r\n", 405)
	if resp.Header.Get("Allow") != "GET, HEAD" || resp.Header.Get("Content-Security-Policy") != baseHeaders(t)["Content-Security-Policy"] {
		t.Fatalf("OPTIONS * headers %v", resp.Header)
	}
}

// unreadBody fails the test if the handler reads request content.
type unreadBody struct {
	t    *testing.T
	read bool
}

func (b *unreadBody) Read(p []byte) (int, error) { b.read = true; return 0, io.EOF }
func (b *unreadBody) Close() error               { return nil }

func TestRequestContentRefused(t *testing.T) {
	h := newHandler(t)
	for _, c := range []struct {
		method, target string
		length         int64
	}{
		{"GET", "/", 1},
		{"GET", "/", -1},
		{"POST", "/", 10},
		{"GET", "/healthz", 1},
		{"GET", "/a/../b", 1},
		{"OPTIONS", "*", 1},
		{"GET", "/api/v1/x", -1},
	} {
		r := httptest.NewRequest(c.method, c.target, nil)
		b := &unreadBody{t: t}
		r.Body, r.ContentLength = b, c.length
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		checkProblem(t, w, http.StatusRequestEntityTooLarge)
		checkBase(t, w, false)
		if w.Header().Get("Connection") != "close" {
			t.Fatalf("%s %s: Connection %q", c.method, c.target, w.Header().Get("Connection"))
		}
		if b.read {
			t.Fatalf("%s %s: handler read request content", c.method, c.target)
		}
	}
	w := do(t, h, req{method: "POST", target: "/"})
	if w.Code != 405 {
		t.Fatalf("POST without content: %d", w.Code)
	}
}

func TestRequestContentRefusedOverConnection(t *testing.T) {
	h := newHandler(t)
	// The declared content never arrives; the response must come at once.
	start := time.Now()
	resp := rawStatus(t, h, "GET / HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\nx", 413)
	if !resp.Close || time.Since(start) > 2*time.Second {
		t.Fatalf("Close %v after %v", resp.Close, time.Since(start))
	}
	rawStatus(t, h, "GET / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nab", 413)
}

func TestHealthDispatch(t *testing.T) {
	h := newHandler(t)
	if w := do(t, h, req{method: "GET", target: "/healthz"}); w.Body.String() != `{"status":"ok"}` {
		t.Fatalf("healthz %q", w.Body.String())
	}
	if w := do(t, h, req{method: "GET", target: "/readyz"}); w.Body.String() != `{"status":"ready"}` {
		t.Fatalf("readyz %q", w.Body.String())
	}
	if w := do(t, h, req{method: "DELETE", target: "/healthz"}); w.Body.String() != `{"status":"ok"}` {
		t.Fatalf("health owns its method check: %d %q", w.Code, w.Body.String())
	}
}

func TestConsoleDisabled(t *testing.T) {
	h := console.NewHandler(nil, stubHealth(`{"status":"ok"}`), stubHealth(`{"status":"ready"}`))
	for _, p := range []string{"/", "/" + jsAsset, "/brand/favicon.ico", "/devices/1"} {
		w := do(t, h, req{method: "GET", target: p, header: map[string]string{"Accept": "text/html"}})
		checkProblem(t, w, 404)
		checkBase(t, w, false)
	}
	if w := do(t, h, req{method: "GET", target: "/healthz"}); w.Code != 200 {
		t.Fatalf("healthz %d", w.Code)
	}
}
