package runtime

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ricevanta/ricevanta/server/internal/buildinfo"
	"github.com/ricevanta/ricevanta/server/internal/transport/console"
)

// syncBuffer collects log output written from several goroutines.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
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

func plaintextConfig(port int, extra string) string {
	return "schema: ricevanta-server-config-v1\nroles: [api]\nlisten:\n  api:\n    address: \"127.0.0.1:" +
		strconv.Itoa(port) + "\"\n    tls:\n      mode: none\n" + extra
}

type running struct {
	addr   string
	cancel context.CancelFunc
	done   chan int
	log    *syncBuffer
}

// start runs Serve in the background and waits for ready.
func start(t *testing.T, o Options) *running {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	logs := &syncBuffer{}
	o.Stderr = logs
	if o.Stdout == nil {
		o.Stdout = io.Discard
	}
	ready := make(chan string, 1)
	o.ready = ready
	done := make(chan int, 1)
	go func() { done <- Serve(ctx, o) }()
	select {
	case addr := <-ready:
		return &running{addr: addr, cancel: cancel, done: done, log: logs}
	case code := <-done:
		cancel()
		t.Fatalf("Serve exited %d before ready:\n%s", code, logs.String())
	case <-time.After(10 * time.Second):
		cancel()
		t.Fatalf("Serve not ready:\n%s", logs.String())
	}
	return nil
}

func (r *running) wait(t *testing.T, within time.Duration) int {
	t.Helper()
	select {
	case code := <-r.done:
		return code
	case <-time.After(within):
		t.Fatalf("Serve still running after %v:\n%s", within, r.log.String())
	}
	return -1
}

func logMessages(t *testing.T, logs string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSuffix(logs, "\n"), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("log line is not JSON: %q", line)
		}
		for _, k := range []string{"time", "level", "msg"} {
			if _, ok := m[k]; !ok {
				t.Fatalf("log line lacks %s: %q", k, line)
			}
		}
		if !catalogue[m["msg"].(string)] {
			t.Fatalf("msg %q is not in the catalogue", m["msg"])
		}
		out = append(out, m)
	}
	return out
}

func hasMsg(t *testing.T, logs, msg string) bool {
	for _, m := range logMessages(t, logs) {
		if m["msg"] == msg {
			return true
		}
	}
	return false
}

// blocker holds requests to /block until released.
type blocker struct {
	entered chan struct{}
	release chan struct{}
	root    http.Handler
}

func newBlocker() *blocker {
	return &blocker{entered: make(chan struct{}, 8), release: make(chan struct{})}
}

func (b *blocker) wrap(h http.Handler) http.Handler {
	b.root = h
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/block" {
			b.entered <- struct{}{}
			<-b.release
			io.WriteString(w, "finished")
			return
		}
		h.ServeHTTP(w, r)
	})
}

func TestShutdownDeadlineMissedExitsOne(t *testing.T) {
	b := newBlocker()
	defer close(b.release)
	port := freePort(t)
	r := start(t, Options{ConfigFlag: writeConfig(t, plaintextConfig(port, "console: {enabled: false}\nshutdown: {timeout_ms: 1000}\n")), ConfigFlagSet: true, wrap: b.wrap})
	go http.Get("http://" + r.addr + "/block")
	<-b.entered
	began := time.Now()
	r.cancel()
	if code := r.wait(t, 10*time.Second); code != ExitFailure {
		t.Fatalf("exit %d, want %d", code, ExitFailure)
	}
	if d := time.Since(began); d < 900*time.Millisecond || d > 3*time.Second {
		t.Fatalf("returned after %v, want about the 1 s deadline", d)
	}
	if !hasMsg(t, r.log.String(), "shutdown_timeout") || hasMsg(t, r.log.String(), "shutdown_complete") {
		t.Fatalf("logs:\n%s", r.log.String())
	}
}

func TestStopDrainsInFlightAndFlipsReadiness(t *testing.T) {
	b := newBlocker()
	port := freePort(t)
	r := start(t, Options{ConfigFlag: writeConfig(t, plaintextConfig(port, "console: {enabled: false}\n")), ConfigFlagSet: true, wrap: b.wrap})
	readyz := func() (int, string) {
		w := httptest.NewRecorder()
		b.root.ServeHTTP(w, httptest.NewRequest("GET", "/readyz", nil))
		return w.Code, w.Body.String()
	}
	if code, body := readyz(); code != 200 || body != `{"status":"ready","roles":{"api":"ready"}}` {
		t.Fatalf("before stop: %d %s", code, body)
	}
	result := make(chan string, 1)
	go func() {
		resp, err := http.Get("http://" + r.addr + "/block")
		if err != nil {
			result <- err.Error()
			return
		}
		defer resp.Body.Close()
		data, _ := io.ReadAll(resp.Body)
		result <- string(data)
	}()
	<-b.entered
	r.cancel()
	deadline := time.Now().Add(5 * time.Second)
	for {
		code, body := readyz()
		if code == 503 && body == `{"status":"stopping","roles":{"api":"stopping"}}` {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("readiness did not flip: %d %s", code, body)
		}
		time.Sleep(10 * time.Millisecond)
	}
	close(b.release)
	if got := <-result; got != "finished" {
		t.Fatalf("in-flight request: %q", got)
	}
	if code := r.wait(t, 10*time.Second); code != ExitOK {
		t.Fatalf("exit %d", code)
	}
	logs := r.log.String()
	for _, m := range []string{"starting", "config_loaded", "listening", "ready", "request", "stop_requested", "shutdown_complete"} {
		if !hasMsg(t, logs, m) {
			t.Errorf("missing %s in:\n%s", m, logs)
		}
	}
}

func TestBlockedRolesNeverStart(t *testing.T) {
	for _, roles := range []string{"api,agent", "api,device", "api,radius", "api,jobs", "jobs"} {
		port := freePort(t)
		logs := &syncBuffer{}
		code := Serve(context.Background(), Options{
			ConfigFlag: writeConfig(t, plaintextConfig(port, "")), ConfigFlagSet: true,
			Environ: []string{"RICEVANTA_SERVER_ROLES=" + roles}, Stderr: logs, Stdout: io.Discard,
		})
		if code != ExitConfig || !strings.Contains(logs.String(), "role_blocked") {
			t.Fatalf("%s: exit %d logs %s", roles, code, logs.String())
		}
		if c, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), 200*time.Millisecond); err == nil {
			c.Close()
			t.Fatalf("%s: listener bound", roles)
		}
	}
}

func TestAdmit(t *testing.T) {
	if err := Admit([]string{"api"}); err != nil {
		t.Fatal(err)
	}
	for role, gate := range map[string]string{
		"agent": "enrollment", "device": "enrollment", "radius": "RAD-02", "jobs": "database",
	} {
		err := Admit([]string{"api", role})
		var re *RoleError
		if !errors.As(err, &re) || re.Role != role || !strings.Contains(err.Error(), "role_blocked") || !strings.Contains(err.Error(), gate) {
			t.Fatalf("%s: %v", role, err)
		}
	}
}

func fixtureSource(t *testing.T) func() (fs.FS, []byte, bool) {
	t.Helper()
	manifest, err := os.ReadFile("../../transport/console/testdata/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	return func() (fs.FS, []byte, bool) {
		return os.DirFS("../../transport/console/testdata/dist"), manifest, true
	}
}

func TestConsoleServedOverPlaintext(t *testing.T) {
	port := freePort(t)
	r := start(t, Options{ConfigFlag: writeConfig(t, plaintextConfig(port, "")), ConfigFlagSet: true, consoleSource: fixtureSource(t)})
	defer func() { r.cancel(); r.wait(t, 10*time.Second) }()
	resp, err := http.Get("http://" + r.addr + "/assets/index-Bx1a2b3c.js")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("Content-Security-Policy") != console.CSP || resp.Header.Get("Strict-Transport-Security") != "" || resp.ProtoMajor != 1 {
		t.Fatalf("%d %v %s", resp.StatusCode, resp.Header, resp.Proto)
	}
	if !hasMsg(t, r.log.String(), "console_verified") {
		t.Fatalf("logs:\n%s", r.log.String())
	}
}

func TestConsoleIdentityMismatchFailsStartup(t *testing.T) {
	logs := &syncBuffer{}
	code := Serve(context.Background(), Options{
		ConfigFlag: writeConfig(t, plaintextConfig(freePort(t), "")), ConfigFlagSet: true,
		consoleSource: fixtureSource(t), identity: &buildinfo.Identity{Version: "0.1.0", Commit: "x", Channel: "master"},
		Stderr: logs, Stdout: io.Discard,
	})
	if code != ExitStartup || !strings.Contains(logs.String(), console.CodeIdentityMismatch) {
		t.Fatalf("exit %d logs %s", code, logs.String())
	}
}

func TestConsoleMissingWithoutTag(t *testing.T) {
	if _, _, ok := console.Embedded(); ok {
		t.Skip("built with ricevanta_console")
	}
	logs := &syncBuffer{}
	code := Serve(context.Background(), Options{
		ConfigFlag: writeConfig(t, plaintextConfig(freePort(t), "")), ConfigFlagSet: true, Stderr: logs, Stdout: io.Discard,
	})
	if code != ExitStartup || !strings.Contains(logs.String(), console.CodeMissing) {
		t.Fatalf("exit %d logs %s", code, logs.String())
	}
	logMessages(t, logs.String())
}

func TestRequestLogFields(t *testing.T) {
	port := freePort(t)
	r := start(t, Options{ConfigFlag: writeConfig(t, plaintextConfig(port, "log: {level: debug}\n")), ConfigFlagSet: true, consoleSource: fixtureSource(t)})
	req, _ := http.NewRequest("GET", "http://"+r.addr+"/assets/index-Bx1a2b3c.js?token=secret-query", nil)
	req.Header.Set("Cookie", "session=secret-cookie")
	req.Header.Set("Authorization", "Bearer secret-header")
	req.Header.Set("Accept-Encoding", "identity")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	r.cancel()
	r.wait(t, 10*time.Second)
	logs := r.log.String()
	for _, s := range []string{"secret-query", "secret-cookie", "secret-header"} {
		if strings.Contains(logs, s) {
			t.Fatalf("log contains %s:\n%s", s, logs)
		}
	}
	var found bool
	for _, m := range logMessages(t, logs) {
		if m["msg"] != "request" {
			continue
		}
		found = true
		if m["method"] != "GET" || m["path"] != "/assets/index-Bx1a2b3c.js" || m["status"] != float64(200) ||
			m["bytes"] != float64(34) || m["remote"] == nil || m["duration_ms"] == nil || m["cache_control"] != "public, max-age=31536000, immutable" {
			t.Fatalf("request record %v", m)
		}
	}
	if !found {
		t.Fatalf("no request record:\n%s", logs)
	}
}

func TestTLSServesHTTP2WithHSTS(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeCertificate(t, dir)
	port := freePort(t)
	doc := "schema: ricevanta-server-config-v1\nroles: [api]\nlisten:\n  api:\n    address: \"127.0.0.1:" + strconv.Itoa(port) +
		"\"\n    tls:\n      mode: file\n      certificate_file: " + certFile + "\n      key_file: " + keyFile + "\n"
	r := start(t, Options{ConfigFlag: writeConfig(t, doc), ConfigFlagSet: true, consoleSource: fixtureSource(t)})
	defer func() { r.cancel(); r.wait(t, 10*time.Second) }()
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: certPool(t, certFile)}, ForceAttemptHTTP2: true}}
	resp, err := client.Get("https://" + r.addr + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.ProtoMajor != 2 || resp.Header.Get("Strict-Transport-Security") != "max-age=31536000" || resp.StatusCode != 200 {
		t.Fatalf("%s %d %v", resp.Proto, resp.StatusCode, resp.Header)
	}
}

func TestOptionsStarReachesRootHandler(t *testing.T) {
	port := freePort(t)
	r := start(t, Options{ConfigFlag: writeConfig(t, plaintextConfig(port, "console: {enabled: false}\n")), ConfigFlagSet: true})
	defer func() { r.cancel(); r.wait(t, 10*time.Second) }()
	c, err := net.Dial("tcp", r.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, "OPTIONS * HTTP/1.1\r\nHost: x\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 405 || resp.Header.Get("Allow") != "GET, HEAD" || resp.Header.Get("Content-Security-Policy") != console.CSP {
		t.Fatalf("%d %v", resp.StatusCode, resp.Header)
	}
}

func TestCheckConfig(t *testing.T) {
	var out, errOut bytes.Buffer
	path := writeConfig(t, plaintextConfig(8080, ""))
	if code := CheckConfig(Options{ConfigFlag: path, ConfigFlagSet: true, Stdout: &out, Stderr: &errOut}); code != ExitOK {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	if !strings.HasPrefix(out.String(), `{"console":{"enabled":true}`) || !strings.HasSuffix(out.String(), "}\n") {
		t.Fatalf("stdout %q", out.String())
	}
	out.Reset()
	if code := CheckConfig(Options{ConfigFlag: path, ConfigFlagSet: true, Environ: []string{"RICEVANTA_SERVER_ROLES=api,jobs"}, Stdout: &out, Stderr: &errOut}); code != ExitConfig || out.Len() != 0 {
		t.Fatalf("blocked role: exit %d stdout %q", code, out.String())
	}
	if code := CheckConfig(Options{ConfigFlag: path, ConfigFlagSet: true, Environ: []string{"RICEVANTA_SERVER_LOG_LEVL=x"}, Stdout: &out, Stderr: &errOut}); code != ExitConfig {
		t.Fatalf("unknown variable: exit %d", code)
	}
}

func TestConsoleManifestCommand(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := ConsoleManifest(Options{consoleSource: fixtureSource(t), Stdout: &out, Stderr: &errOut}); code != ExitOK {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	want, _ := os.ReadFile("../../transport/console/testdata/manifest.json")
	if out.String() != string(want) {
		t.Fatal("console-manifest changed the embedded bytes")
	}
	out.Reset()
	if _, _, ok := console.Embedded(); !ok {
		if code := ConsoleManifest(Options{Stdout: &out, Stderr: &errOut}); code != ExitStartup || out.Len() != 0 {
			t.Fatalf("untagged: exit %d", code)
		}
	}
}
