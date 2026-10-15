//go:build unix

package runtime

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"
)

// TLS key files are admitted only where the POSIX key-file rule can be
// evaluated; runtime_windows_test.go checks the refusal on Windows.
func TestTLSServesHTTP2WithHSTS(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeCertificate(t, dir)
	port := freePort(t)
	doc := "schema: ricevanta-server-config-v1\nroles: [api]\nlisten:\n  api:\n    address: \"127.0.0.1:" + strconv.Itoa(port) +
		"\"\n    tls:\n      mode: file\n      certificate_file: " + certFile + "\n      key_file: " + keyFile + "\n"
	r := start(t, Options{ConfigFlag: writeConfig(t, doc), ConfigFlagSet: true, consoleSource: fixtureSource(t), identity: fixtureIdentity})
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

// TestStopAtEveryStartupBoundary injects a stop request at each startup step
// boundary of spec section 4. Startup must end there with exit 0, log
// stop_requested and shutdown_complete, never report ready and leave the
// listener closed. The full path (configuration, console, TLS, listener) is
// exercised so every boundary is reached.
func TestStopAtEveryStartupBoundary(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeCertificate(t, dir)
	for _, step := range []string{"config", "roles", "console", "tls", "listen", "serve"} {
		t.Run(step, func(t *testing.T) {
			port := freePort(t)
			doc := "schema: ricevanta-server-config-v1\nroles: [api]\nlisten:\n  api:\n    address: \"127.0.0.1:" + strconv.Itoa(port) +
				"\"\n    tls:\n      mode: file\n      certificate_file: " + certFile + "\n      key_file: " + keyFile + "\n"
			if step == "config" {
				// The stop during loading must log before log.level error applies.
				doc += "log: {level: error}\n"
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var seen []string
			logs := &syncBuffer{}
			code := Serve(ctx, Options{
				ConfigFlag: writeConfig(t, doc), ConfigFlagSet: true, Stderr: logs, Stdout: io.Discard,
				consoleSource: fixtureSource(t), identity: fixtureIdentity,
				atStep: func(s string) {
					seen = append(seen, s)
					if s == step {
						cancel()
					}
				},
			})
			if code != ExitOK {
				t.Fatalf("exit %d:\n%s", code, logs.String())
			}
			if seen[len(seen)-1] != step {
				t.Fatalf("startup continued past %s: %v", step, seen)
			}
			var stopStep string
			for _, m := range logMessages(t, logs.String()) {
				switch m["msg"] {
				case "ready":
					t.Fatalf("reported ready after a stop at %s", step)
				case "stop_requested":
					stopStep, _ = m["step"].(string)
				}
			}
			if stopStep != step || !hasMsg(t, logs.String(), "shutdown_complete") {
				t.Fatalf("logs:\n%s", logs.String())
			}
			l, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(port))
			if err != nil {
				t.Fatalf("listener left open after a stop at %s: %v", step, err)
			}
			l.Close()
		})
	}
}

// TestConfigErrorLoggedBeforeLevelApplies: a configuration that names
// log.level error but fails validation still logs startup_failed as JSON.
func TestConfigErrorLoggedBeforeLevelApplies(t *testing.T) {
	logs := &syncBuffer{}
	doc := "schema: ricevanta-server-config-v1\nroles: [api]\nlisten: {api: {address: \"0.0.0.0:8080\", tls: {mode: none}}}\nlog: {level: error}\n"
	code := Serve(context.Background(), Options{ConfigFlag: writeConfig(t, doc), ConfigFlagSet: true, Stderr: logs, Stdout: io.Discard})
	if code != ExitConfig || !hasMsg(t, logs.String(), "starting") || !hasMsg(t, logs.String(), "startup_failed") {
		t.Fatalf("exit %d logs:\n%s", code, logs.String())
	}
}
