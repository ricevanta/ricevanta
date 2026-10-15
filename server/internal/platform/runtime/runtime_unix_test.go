//go:build unix

package runtime

import (
	"crypto/tls"
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
