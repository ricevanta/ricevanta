//go:build unix

package main_test

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// plainClient opens one connection per request. The default transport may
// dial a spare connection that never sends a request; net/http's Shutdown
// counts such a connection as idle only after 5 s, which would make stop
// timings depend on that race.
var plainClient = &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}

var catalogue = map[string]bool{
	"starting": true, "config_loaded": true, "console_verified": true, "listening": true, "ready": true,
	"request": true, "stop_requested": true, "shutdown_complete": true, "shutdown_timeout": true, "startup_failed": true,
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func writeConfig(t *testing.T, doc string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "server.yaml")
	if err := os.WriteFile(p, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func plaintext(port int, extra string) string {
	return "schema: ricevanta-server-config-v1\nroles: [api]\nlisten:\n  api:\n    address: \"127.0.0.1:" +
		strconv.Itoa(port) + "\"\n    tls:\n      mode: none\n" + extra
}

func withTLS(port int, certFile, keyFile, extra string) string {
	return "schema: ricevanta-server-config-v1\nroles: [api]\nlisten:\n  api:\n    address: \"127.0.0.1:" +
		strconv.Itoa(port) + "\"\n    tls:\n      mode: file\n      certificate_file: " + certFile +
		"\n      key_file: " + keyFile + "\n" + extra
}

func writeCertificate(t *testing.T) (certFile, keyFile string, pool *x509.CertPool) {
	t.Helper()
	dir := t.TempDir()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ricevanta-test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certFile, keyFile = filepath.Join(dir, "api.crt"), filepath.Join(dir, "api.key")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(certFile, certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}), 0o600); err != nil {
		t.Fatal(err)
	}
	pool = x509.NewCertPool()
	pool.AppendCertsFromPEM(certPEM)
	return certFile, keyFile, pool
}

// server is a running ricevanta-server process.
type server struct {
	cmd    *exec.Cmd
	addr   string
	mu     sync.Mutex
	lines  []string
	exited chan int
}

func (s *server) logs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.lines...)
}

func (s *server) logText() string { return strings.Join(s.logs(), "\n") }

func startServer(t *testing.T, bin, config string, env ...string) *server {
	t.Helper()
	cmd := exec.Command(bin, "serve", "--config", config)
	cmd.Env = env
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	s := &server{cmd: cmd, exited: make(chan int, 1)}
	ready := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(stderr)
		for sc.Scan() {
			line := sc.Text()
			s.mu.Lock()
			s.lines = append(s.lines, line)
			s.mu.Unlock()
			var m map[string]any
			if json.Unmarshal([]byte(line), &m) == nil {
				if m["msg"] == "listening" {
					if a, ok := m["address"].(string); ok {
						s.addr = a
					}
				}
				if m["msg"] == "ready" {
					ready <- s.addr
				}
			}
		}
		err := cmd.Wait()
		code := 0
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			code = exit.ExitCode()
		}
		s.exited <- code
	}()
	t.Cleanup(func() {
		cmd.Process.Kill()
	})
	select {
	case <-ready:
	case code := <-s.exited:
		t.Fatalf("server exited %d before ready:\n%s", code, s.logText())
	case <-time.After(15 * time.Second):
		t.Fatalf("server not ready:\n%s", s.logText())
	}
	return s
}

func (s *server) stop(t *testing.T) {
	t.Helper()
	if err := s.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
}

func (s *server) wait(t *testing.T, within time.Duration) int {
	t.Helper()
	select {
	case code := <-s.exited:
		return code
	case <-time.After(within):
		t.Fatalf("server still running after %v:\n%s", within, s.logText())
	}
	return -1
}

func checkLogs(t *testing.T, lines []string, want ...string) {
	t.Helper()
	seen := map[string]bool{}
	for _, line := range lines {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("log line is not one JSON object: %q", line)
		}
		for _, k := range []string{"time", "level", "msg"} {
			if _, ok := m[k]; !ok {
				t.Fatalf("log line lacks %s: %q", k, line)
			}
		}
		msg, _ := m["msg"].(string)
		if !catalogue[msg] {
			t.Fatalf("msg %q not in the catalogue", msg)
		}
		seen[msg] = true
	}
	for _, w := range want {
		if !seen[w] {
			t.Errorf("no %s in logs:\n%s", w, strings.Join(lines, "\n"))
		}
	}
}

func runConfig(t *testing.T, bin, config string, env ...string) result {
	t.Helper()
	cmd := exec.Command(bin, "serve", "--config", config)
	cmd.Env = env
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	done := make(chan error, 1)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		code := 0
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			code = exit.ExitCode()
		}
		return result{stdout.Bytes(), stderr.Bytes(), code}
	case <-time.After(10 * time.Second):
		cmd.Process.Kill()
		t.Fatalf("serve did not exit:\n%s", stderr.String())
	}
	return result{}
}

func TestHealthAndReadiness(t *testing.T) {
	s := startServer(t, serverBin, writeConfig(t, plaintext(freePort(t), "console: {enabled: false}\n")))
	for path, want := range map[string]string{
		"/healthz": `{"status":"ok"}`,
		"/readyz":  `{"status":"ready","roles":{"api":"ready"}}`,
	} {
		resp, err := plainClient.Get("http://" + s.addr + path)
		if err != nil {
			t.Fatal(err)
		}
		data, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 || string(data) != want {
			t.Fatalf("%s: %d %s", path, resp.StatusCode, data)
		}
		if resp.Header.Get("Cache-Control") != "no-store" || resp.Header.Get("Content-Type") != "application/json" ||
			resp.Header.Get("X-Content-Type-Options") != "nosniff" {
			t.Fatalf("%s headers %v", path, resp.Header)
		}
		for k, v := range resp.Header {
			if strings.Contains(strings.Join(v, ","), "0.0.0-local") || k == "Server" {
				t.Fatalf("%s discloses %s: %v", path, k, v)
			}
		}
		if resp.ProtoMajor != 1 || resp.Header.Get("Strict-Transport-Security") != "" {
			t.Fatalf("plaintext: %s HSTS %q", resp.Proto, resp.Header.Get("Strict-Transport-Security"))
		}
	}
	for _, path := range []string{"/metrics", "/api/v1/devices", "/agent/v1/checkin", "/ext/x"} {
		resp, err := plainClient.Get("http://" + s.addr + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 404 {
			t.Fatalf("%s: %d", path, resp.StatusCode)
		}
	}
	s.stop(t)
	if code := s.wait(t, 5*time.Second); code != 0 {
		t.Fatalf("exit %d", code)
	}
	checkLogs(t, s.logs(), "starting", "config_loaded", "listening", "ready", "request", "stop_requested", "shutdown_complete")
}

func TestStartupRefusals(t *testing.T) {
	cert, key, _ := writeCertificate(t)
	world := filepath.Join(filepath.Dir(key), "world.key")
	data, _ := os.ReadFile(key)
	os.WriteFile(world, data, 0o600)
	os.Chmod(world, 0o644)
	port := freePort(t)
	cases := []struct {
		name, config string
		env          []string
		code         int
		contains     []string
	}{
		{"blocked jobs", "schema: ricevanta-server-config-v1\nroles: [api, jobs]\nlisten: {api: {address: \"127.0.0.1:" + strconv.Itoa(port) + "\", tls: {mode: none}}}\nconsole: {enabled: false}\n",
			nil, 2, []string{"role_blocked", "jobs", "database"}},
		{"blocked agent by environment", plaintext(port, "console: {enabled: false}\n"), []string{"RICEVANTA_SERVER_ROLES=api,agent"}, 2, []string{"role_blocked", "agent"}},
		{"no roles", "schema: ricevanta-server-config-v1\nlisten: {api: {address: \"127.0.0.1:" + strconv.Itoa(port) + "\", tls: {mode: none}}}\n",
			nil, 2, []string{"roles"}},
		{"plaintext off loopback", strings.Replace(plaintext(port, ""), "127.0.0.1", "0.0.0.0", 1), nil, 2, []string{"plaintext_requires_loopback"}},
		{"misspelled variable", plaintext(port, ""), []string{"RICEVANTA_SERVER_LISTEN_API_ADRESS=127.0.0.1:1"}, 2, []string{"RICEVANTA_SERVER_LISTEN_API_ADRESS"}},
		{"world-readable key", withTLS(port, cert, world, "console: {enabled: false}\n"), nil, 3, []string{"key_file_rejected"}},
		{"console without tag", plaintext(port, ""), nil, 3, []string{"console_missing"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := runConfig(t, serverBin, writeConfig(t, c.config), c.env...)
			if r.code != c.code {
				t.Fatalf("exit %d, want %d:\n%s", r.code, c.code, r.stderr)
			}
			for _, s := range c.contains {
				if !bytes.Contains(r.stderr, []byte(s)) {
					t.Errorf("stderr lacks %q:\n%s", s, r.stderr)
				}
			}
			if len(r.stdout) != 0 {
				t.Errorf("stdout %q", r.stdout)
			}
			lines := strings.Split(strings.TrimSpace(string(r.stderr)), "\n")
			checkLogs(t, lines, "starting", "startup_failed")
			if strings.Contains(string(r.stderr), "127.0.0.1:1") {
				t.Errorf("environment value logged")
			}
		})
	}
}

func TestCheckConfigCommand(t *testing.T) {
	cfg := writeConfig(t, plaintext(8080, ""))
	r := run(t, nil, "check-config", "--config", cfg)
	if r.code != 0 || !bytes.HasPrefix(r.stdout, []byte(`{"console":{"enabled":true},`)) {
		t.Fatalf("exit %d stdout %s stderr %s", r.code, r.stdout, r.stderr)
	}
	r = run(t, []string{"RICEVANTA_SERVER_CONFIG=" + cfg}, "check-config")
	if r.code != 0 {
		t.Fatalf("config from environment: exit %d %s", r.code, r.stderr)
	}
	r = run(t, []string{"RICEVANTA_SERVER_CONFIG=/nonexistent.yaml"}, "check-config", "--config", cfg)
	if r.code != 0 {
		t.Fatalf("--config must win over RICEVANTA_SERVER_CONFIG: exit %d %s", r.code, r.stderr)
	}
	r = run(t, nil, "check-config", "--config", writeConfig(t, "schema: x\n"))
	if r.code != 2 || len(r.stdout) != 0 {
		t.Fatalf("invalid: exit %d stdout %q", r.code, r.stdout)
	}
}

func TestConsoleManifestWithoutTag(t *testing.T) {
	r := run(t, nil, "console-manifest")
	if r.code != 3 || len(r.stdout) != 0 || !bytes.Contains(r.stderr, []byte("console_missing")) {
		t.Fatalf("exit %d stdout %q stderr %q", r.code, r.stdout, r.stderr)
	}
}

// refuseOverRaw sends a request that declares content, then keeps trickling
// it one piece per second. It returns when the 413 arrives and when the
// server closed the connection, measured from the response.
func refuseOverRaw(t *testing.T, addr, head, piece string) (sinceStart, closeAfterResponse time.Duration) {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	start := time.Now()
	if _, err := io.WriteString(c, head); err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tick.C:
				if _, err := io.WriteString(c, piece); err != nil {
					return
				}
			}
		}
	}()
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := time.Now()
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 413 || !resp.Close {
		t.Fatalf("status %d close %v", resp.StatusCode, resp.Close)
	}
	_, err = io.Copy(io.Discard, br)
	if err != nil && !errors.Is(err, syscall.ECONNRESET) {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			t.Fatal("server kept the connection open")
		}
	}
	return got.Sub(start), time.Since(got)
}

func TestContentRefusalOverHTTP1(t *testing.T) {
	s := startServer(t, serverBin, writeConfig(t, plaintext(freePort(t), "console: {enabled: false}\n")))
	for _, c := range []struct{ name, head, piece string }{
		{"content-length", "GET / HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\nx", "x"},
		{"chunked", "GET /healthz HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n", "1\r\nx\r\n"},
	} {
		t.Run(c.name, func(t *testing.T) {
			respAt, closeAfter := refuseOverRaw(t, s.addr, c.head, c.piece)
			if respAt > 500*time.Millisecond {
				t.Errorf("413 after %v, want at once", respAt)
			}
			if closeAfter > time.Second {
				t.Errorf("connection closed %v after the response, want within 1 s", closeAfter)
			}
		})
	}
	s.stop(t)
	if code := s.wait(t, 5*time.Second); code != 0 {
		t.Fatalf("exit %d", code)
	}
}

func TestStopDuringTrickle(t *testing.T) {
	s := startServer(t, serverBin, writeConfig(t, plaintext(freePort(t), "console: {enabled: false}\n")))
	c, err := net.Dial("tcp", s.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, "GET / HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\nx")
	go func() {
		for i := 0; i < 9; i++ {
			time.Sleep(time.Second)
			if _, err := io.WriteString(c, "x"); err != nil {
				return
			}
		}
	}()
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil || resp.StatusCode != 413 {
		t.Fatalf("%v %v", resp, err)
	}
	began := time.Now()
	s.stop(t)
	if code := s.wait(t, 5*time.Second); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if d := time.Since(began); d > 2*time.Second {
		t.Fatalf("exit after %v, want within 2 s", d)
	}
}

// h2frame writes one HTTP/2 frame (RFC 9113 section 4.1).
func h2frame(w io.Writer, typ, flags byte, stream uint32, payload []byte) error {
	hdr := []byte{byte(len(payload) >> 16), byte(len(payload) >> 8), byte(len(payload)), typ, flags,
		byte(stream >> 24), byte(stream >> 16), byte(stream >> 8), byte(stream)}
	_, err := w.Write(append(hdr, payload...))
	return err
}

// hpackLiteral encodes a literal header field without indexing and with a
// literal name, without Huffman coding (RFC 7541 section 6.2.2).
func hpackLiteral(name, value string) []byte {
	b := []byte{0x00, byte(len(name))}
	b = append(b, name...)
	b = append(b, byte(len(value)))
	return append(b, value...)
}

// TestTLSHTTP2WithHSTSAndContentRefusal checks HTTP/2 negotiation and HSTS
// with Go's client, then refuses declared content over a raw HTTP/2
// connection whose client never closes it, so the measured close is the
// server's own.
func TestTLSHTTP2WithHSTSAndContentRefusal(t *testing.T) {
	cert, key, pool := writeCertificate(t)
	s := startServer(t, serverBin, writeConfig(t, withTLS(freePort(t), cert, key, "console: {enabled: false}\n")))
	tr := &http.Transport{ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{RootCAs: pool}}
	defer tr.CloseIdleConnections()
	resp, err := (&http.Client{Transport: tr}).Get("https://" + s.addr + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.ProtoMajor != 2 || resp.Header.Get("Strict-Transport-Security") != "max-age=31536000" {
		t.Fatalf("%s HSTS %q", resp.Proto, resp.Header.Get("Strict-Transport-Security"))
	}
	tr.CloseIdleConnections()

	c, err := tls.Dial("tcp", s.addr, &tls.Config{RootCAs: pool, NextProtos: []string{"h2"}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if c.ConnectionState().NegotiatedProtocol != "h2" {
		t.Fatalf("ALPN %q", c.ConnectionState().NegotiatedProtocol)
	}
	io.WriteString(c, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	h2frame(c, 0x4, 0, 0, nil) // SETTINGS
	var block []byte
	for _, f := range [][2]string{{":method", "POST"}, {":scheme", "https"}, {":path", "/"}, {":authority", "x"}} {
		block = append(block, hpackLiteral(f[0], f[1])...)
	}
	start := time.Now()
	h2frame(c, 0x1, 0x4, 1, block)     // HEADERS, END_HEADERS, no END_STREAM: content follows
	h2frame(c, 0x0, 0, 1, []byte("x")) // DATA without END_STREAM; the rest never comes
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	var ended time.Time
	var body []byte
	head := make([]byte, 9)
	for {
		if _, err := io.ReadFull(c, head); err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				t.Fatal("server kept the HTTP/2 connection open for 10 s")
			}
			break
		}
		n := int(head[0])<<16 | int(head[1])<<8 | int(head[2])
		payload := make([]byte, n)
		if _, err := io.ReadFull(c, payload); err != nil {
			break
		}
		typ, flags, stream := head[3], head[4], uint32(head[5]&0x7f)<<24|uint32(head[6])<<16|uint32(head[7])<<8|uint32(head[8])
		switch {
		case typ == 0x4 && flags&0x1 == 0:
			h2frame(c, 0x4, 0x1, 0, nil) // ACK the server's SETTINGS
		case typ == 0x0 && stream == 1:
			body = append(body, payload...)
			if flags&0x1 != 0 {
				ended = time.Now()
			}
		}
	}
	closed := time.Now()
	if ended.IsZero() || !bytes.Contains(body, []byte(`"status":413`)) {
		t.Fatalf("no complete 413 response; body %q", body)
	}
	if d := ended.Sub(start); d > 500*time.Millisecond {
		t.Errorf("413 after %v, want at once", d)
	}
	if d := closed.Sub(ended); d > 2*time.Second {
		t.Errorf("server closed the HTTP/2 connection %v after the stream ended, want within 2 s", d)
	}
	s.stop(t)
	if code := s.wait(t, 5*time.Second); code != 0 {
		t.Fatalf("exit %d", code)
	}
}

func TestStalledTLSHandshakeDropped(t *testing.T) {
	cert, key, _ := writeCertificate(t)
	s := startServer(t, serverBin, writeConfig(t, withTLS(freePort(t), cert, key, "console: {enabled: false}\nhttp: {read_header_timeout_ms: 1000}\n")))
	c, err := net.Dial("tcp", s.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	start := time.Now()
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = c.Read(make([]byte, 1))
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatal("stalled handshake not dropped within 5 s")
	}
	if d := time.Since(start); d < 900*time.Millisecond || d > 2500*time.Millisecond {
		t.Fatalf("dropped after %v, want about read_header_timeout_ms", d)
	}
	s.stop(t)
	s.wait(t, 5*time.Second)
}

// taggedBinary builds ricevanta-server with -tags ricevanta_console in a
// temporary copy of the module whose dist/ holds the console fixture plus
// a large unlisted asset, with manifest.json written beside it.
var (
	taggedOnce sync.Once
	taggedBin  string
	taggedErr  error
	largeSize  = 64 << 20
)

func copyDir(src, dst string) error {
	return filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o644)
	})
}

func buildTagged() (string, error) {
	root, err := os.MkdirTemp(testDir, "tagged-")
	if err != nil {
		return "", err
	}
	for _, dir := range []string{"cmd/ricevanta-server", "internal/buildinfo", "internal/platform", "internal/transport"} {
		if err := copyDir(filepath.Join("../..", dir), filepath.Join(root, dir)); err != nil {
			return "", err
		}
	}
	for _, f := range []string{"go.mod", "go.sum"} {
		data, err := os.ReadFile(filepath.Join("../..", f))
		if err != nil {
			return "", err
		}
		if err := os.WriteFile(filepath.Join(root, f), data, 0o644); err != nil {
			return "", err
		}
	}
	pkg := filepath.Join(root, "internal/transport/console")
	dist := filepath.Join(pkg, "dist")
	if err := copyDir(filepath.Join(pkg, "testdata/dist"), dist); err != nil {
		return "", err
	}
	large := bytes.Repeat([]byte("ricevanta large asset\n"), largeSize/22+1)[:largeSize]
	if err := os.WriteFile(filepath.Join(dist, "assets/large.txt"), large, 0o644); err != nil {
		return "", err
	}
	type entry struct {
		Path   string `json:"path"`
		SHA256 string `json:"sha256"`
		Size   int    `json:"size"`
	}
	var entries []entry
	err = filepath.WalkDir(dist, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dist, p)
		sum := sha256.Sum256(data)
		entries = append(entries, entry{filepath.ToSlash(rel), hex.EncodeToString(sum[:]), len(data)})
		return nil
	})
	if err != nil {
		return "", err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	manifest, _ := json.Marshal(struct {
		Files  []entry `json:"files"`
		Schema string  `json:"schema"`
	}{entries, "ricevanta-console-manifest-v1"})
	if err := os.WriteFile(filepath.Join(pkg, "manifest.json"), append(manifest, '\n'), 0o644); err != nil {
		return "", err
	}
	bin := filepath.Join(root, "ricevanta-server")
	cmd := exec.Command("go", "build", "-tags", "ricevanta_console", "-trimpath", "-buildvcs=false", "-o", bin, "./cmd/ricevanta-server")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "GOPROXY=off", "GOFLAGS=-mod=readonly")
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("%v\n%s", err, out)
	}
	return bin, nil
}

func tagged(t *testing.T) string {
	t.Helper()
	taggedOnce.Do(func() { taggedBin, taggedErr = buildTagged() })
	if taggedErr != nil {
		t.Fatal(taggedErr)
	}
	return taggedBin
}

func TestTaggedBinaryServesConsole(t *testing.T) {
	bin := tagged(t)
	s := startServer(t, bin, writeConfig(t, plaintext(freePort(t), "")))
	csp, err := os.ReadFile("../../../console/security/csp.txt")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := plainClient.Get("http://" + s.addr + "/assets/index-Bx1a2b3c.js")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("Content-Security-Policy") != strings.TrimSuffix(string(csp), "\n") ||
		resp.Header.Get("Cache-Control") != "public, max-age=31536000, immutable" {
		t.Fatalf("%d %v", resp.StatusCode, resp.Header)
	}
	out, err := exec.Command(bin, "console-manifest").Output()
	if err != nil || !bytes.HasPrefix(out, []byte(`{"files":[`)) || !bytes.HasSuffix(out, []byte("}\n")) {
		t.Fatalf("console-manifest: %v %q", err, out[:min(len(out), 40)])
	}
	s.stop(t)
	if code := s.wait(t, 5*time.Second); code != 0 {
		t.Fatalf("exit %d", code)
	}
	checkLogs(t, s.logs(), "console_verified", "shutdown_complete")
}

func TestStopLetsInFlightRequestFinish(t *testing.T) {
	bin := tagged(t)
	s := startServer(t, bin, writeConfig(t, plaintext(freePort(t), "")))
	c, err := net.Dial("tcp", s.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, "GET /assets/large.txt HTTP/1.1\r\nHost: x\r\n\r\n")
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("%v %v", resp, err)
	}
	s.stop(t)
	// Read slowly at first so the transfer is still running after SIGTERM.
	var n int64
	buf := make([]byte, 1<<20)
	for {
		k, err := resp.Body.Read(buf)
		n += int64(k)
		if n < 8<<20 {
			time.Sleep(20 * time.Millisecond)
		}
		if err != nil {
			break
		}
	}
	if n != int64(largeSize) {
		t.Fatalf("received %d of %d bytes", n, largeSize)
	}
	if code := s.wait(t, 10*time.Second); code != 0 {
		t.Fatalf("exit %d", code)
	}
	checkLogs(t, s.logs(), "stop_requested", "shutdown_complete")
}

func TestStalledReaderDoesNotHoldShutdown(t *testing.T) {
	bin := tagged(t)
	s := startServer(t, bin, writeConfig(t, plaintext(freePort(t), "")))
	c, err := net.Dial("tcp", s.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if tc, ok := c.(*net.TCPConn); ok {
		tc.SetReadBuffer(4096)
	}
	io.WriteString(c, "GET /assets/large.txt HTTP/1.1\r\nHost: x\r\n\r\n")
	time.Sleep(500 * time.Millisecond)
	began := time.Now()
	s.stop(t)
	code := s.wait(t, 15*time.Second)
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, s.logText())
	}
	if d := time.Since(began); d > 12*time.Second {
		t.Fatalf("stalled reader held shutdown for %v", d)
	}
	checkLogs(t, s.logs(), "shutdown_complete")
}

// smallReceiveBuffer dials with a 4 KiB receive buffer set before connect,
// so a client that stops reading stalls the server's writes quickly.
var smallReceiveBuffer = &net.Dialer{Control: func(network, address string, c syscall.RawConn) error {
	var serr error
	err := c.Control(func(fd uintptr) {
		serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, 4096)
	})
	if err != nil {
		return err
	}
	return serr
}}

// TestHTTP2StalledReaderDoesNotHoldShutdown opens an HTTP/2 connection that
// grants the largest flow-control windows, requests the large asset on four
// streams and never reads. The write-progress bound must still free the
// streams and the connection, so SIGTERM ends in shutdown_complete and exit
// 0 well before the 20 s shutdown deadline.
func TestHTTP2StalledReaderDoesNotHoldShutdown(t *testing.T) {
	bin := tagged(t)
	cert, key, pool := writeCertificate(t)
	s := startServer(t, bin, writeConfig(t, withTLS(freePort(t), cert, key, "")))
	raw, err := smallReceiveBuffer.Dial("tcp", s.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	c := tls.Client(raw, &tls.Config{RootCAs: pool, ServerName: "127.0.0.1", NextProtos: []string{"h2"}})
	if err := c.Handshake(); err != nil {
		t.Fatal(err)
	}
	if c.ConnectionState().NegotiatedProtocol != "h2" {
		t.Fatalf("ALPN %q", c.ConnectionState().NegotiatedProtocol)
	}
	io.WriteString(c, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	h2frame(c, 0x4, 0, 0, []byte{0, 4, 0x7f, 0xff, 0xff, 0xff}) // SETTINGS_INITIAL_WINDOW_SIZE = 2^31-1
	inc := uint32(0x7fffffff - 65535)
	h2frame(c, 0x8, 0, 0, []byte{byte(inc >> 24), byte(inc >> 16), byte(inc >> 8), byte(inc)}) // connection WINDOW_UPDATE
	for _, id := range []uint32{1, 3, 5, 7} {
		var block []byte
		for _, f := range [][2]string{{":method", "GET"}, {":scheme", "https"}, {":path", "/assets/large.txt"}, {":authority", "x"}} {
			block = append(block, hpackLiteral(f[0], f[1])...)
		}
		h2frame(c, 0x1, 0x5, id, block) // HEADERS, END_STREAM | END_HEADERS
	}
	time.Sleep(2 * time.Second)
	began := time.Now()
	s.stop(t)
	code := s.wait(t, 25*time.Second)
	if code != 0 {
		t.Fatalf("exit %d after %v:\n%s", code, time.Since(began), s.logText())
	}
	if d := time.Since(began); d > 15*time.Second {
		t.Fatalf("stalled HTTP/2 reader held shutdown for %v", d)
	}
	checkLogs(t, s.logs(), "shutdown_complete")
}

// TestSlowSteadyReaderReceivesWholeBody reads the 64 MiB asset at a steady
// pace that takes about 13 s in total. The write deadline moves forward
// after each 16 KiB, so a client that keeps making progress is never cut
// off by the 10 s bound.
func TestSlowSteadyReaderReceivesWholeBody(t *testing.T) {
	bin := tagged(t)
	s := startServer(t, bin, writeConfig(t, plaintext(freePort(t), "")))
	c, err := net.Dial("tcp", s.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, "GET /assets/large.txt HTTP/1.1\r\nHost: x\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("%v %v", resp, err)
	}
	const total = 13 * time.Second
	rate := float64(largeSize) / total.Seconds()
	start := time.Now()
	var n int64
	buf := make([]byte, 64<<10)
	for {
		k, err := resp.Body.Read(buf)
		n += int64(k)
		if err != nil {
			break
		}
		if ahead := time.Duration(float64(n)/rate*float64(time.Second)) - time.Since(start); ahead > 0 {
			time.Sleep(ahead)
		}
	}
	elapsed := time.Since(start)
	if n != int64(largeSize) {
		t.Fatalf("received %d of %d bytes in %v", n, largeSize, elapsed)
	}
	if elapsed < 11*time.Second {
		t.Fatalf("transfer took %v; the test needs more than 10 s to prove the deadline moves", elapsed)
	}
	s.stop(t)
	if code := s.wait(t, 10*time.Second); code != 0 {
		t.Fatalf("exit %d", code)
	}
}
