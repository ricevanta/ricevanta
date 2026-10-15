package runtime

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"debug/buildinfo"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ricevanta/ricevanta/server/internal/platform/config"
)

type stalledLog struct{ stage string }

func (w stalledLog) Write(p []byte) (int, error) {
	if strings.Contains(string(p), w.stage) {
		select {}
	}
	return os.Stderr.Write(p)
}

// The helper is a test executable, never a production command or environment
// hook. It calls the production lifecycle with the executable's real watchdog.
func TestStopProcessHelper(t *testing.T) {
	mode := os.Getenv("RICEVANTA_TEST_STOP_HELPER")
	if mode == "" {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { bufio.NewReader(os.Stdin).ReadString('\n'); cancel() }()
	entered := func() { fmt.Fprintln(os.Stdout, "entered") }
	block := func() { entered(); select {} }
	path := writeConfig(t, plaintextConfig(12345, "console: {enabled: false}\nshutdown: {timeout_ms: 1000}\n"))
	o := Options{ConfigFlag: path, ConfigFlagSet: true, Stdout: io.Discard, Stderr: os.Stderr, ProcessExit: os.Exit}
	switch mode {
	case "config", "pipe":
		o.configLoader = func() (config.Config, error) {
			if mode == "pipe" {
				reader, writer, err := os.Pipe()
				if err != nil {
					panic(err)
				}
				defer reader.Close()
				defer writer.Close()
				entered()
				var b [1]byte
				_, err = reader.Read(b[:])
				runtime.KeepAlive(writer)
				return config.Config{}, err
			}
			block()
			return config.Config{}, nil
		}
	case "tls":
		o.configLoader = func() (config.Config, error) {
			cfg, err := loadConfig(o)
			cfg.Listen.API.TLS.Mode = "file"
			return cfg, err
		}
		o.tlsLoader = func(config.TLS) (*tls.Config, error) { block(); return nil, nil }
	case "cleanup", "join":
		ln := &heldListener{mode: mode, closed: make(chan struct{}), accepted: make(chan struct{})}
		o.listener = func(string, string) (net.Listener, error) { return ln, nil }
		o.atStep = func(step string) {
			if step == "serve" {
				<-ln.accepted
				entered()
				<-ctx.Done()
			}
		}
	case "stderr", "complete", "cancel":
		// Hold a real startup operation after publication, without opening sockets.
		o.atStep = func(step string) {
			if step != "tls" {
				return
			}
			entered()
			<-ctx.Done()
		}
		if mode == "stderr" {
			o.Stderr = stalledLog{stage: "stop_requested"}
		}
		if mode == "complete" {
			o.Stderr = stalledLog{stage: "shutdown_complete"}
		}
	default:
		panic(mode)
	}
	code := Serve(ctx, o)
	if mode != "cancel" {
		// The helper deliberately refuses to exit on a library result, proving
		// the independent executable watchdog exits without joining its caller.
		select {}
	}
	os.Exit(code)
}

// Build a separate helper: a race-instrumented os.Exit(0) runs race finalization
// while the watchdog stays armed. That timing is not the release stop contract.
// Keep the outer suite and the in-process controller tests race-instrumented.
func buildStopProcessHelper(t *testing.T) string {
	t.Helper()
	helper := filepath.Join(t.TempDir(), "stop-helper.exe")
	cmd := exec.Command("go", "test", "-c", "-race=false", "-trimpath", "-buildvcs=false", "-o", helper, ".")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build stop helper: %v\n%s", err, output)
	}
	info, err := buildinfo.ReadFile(helper)
	if err != nil {
		t.Fatal(err)
	}
	settings := make(map[string]string)
	for _, setting := range info.Settings {
		settings[setting.Key] = setting.Value
	}
	if settings["-race"] == "true" || settings["-trimpath"] != "true" {
		t.Fatalf("stop helper must use the release build configuration: %v", info.Settings)
	}
	t.Logf("stop helper toolchain=%s OS=%s race=false trimpath=true buildvcs=false", info.GoVersion, runtime.GOOS)
	return helper
}

func TestStopProcessDeadline(t *testing.T) {
	helper := buildStopProcessHelper(t)
	for _, mode := range []string{"config", "pipe", "tls", "cleanup", "join", "stderr", "complete", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			cmd := exec.Command(helper, "-test.run=^TestStopProcessHelper$")
			cmd.Env = append(os.Environ(), "RICEVANTA_TEST_STOP_HELPER="+mode)
			input, err := cmd.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			output, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			var logs bytes.Buffer
			cmd.Stderr = &logs
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { cmd.Process.Kill(); input.Close() }()
			entered := make(chan string, 1)
			go func() { line, _ := bufio.NewReader(output).ReadString('\n'); entered <- line }()
			select {
			case line := <-entered:
				if line != "entered\n" {
					t.Fatalf("helper entry %q: %s", line, logs.String())
				}
			case <-time.After(5 * time.Second):
				t.Fatal("helper did not enter operation")
			}
			budget := time.Second
			if mode == "config" || mode == "pipe" {
				budget = 20 * time.Second
			}
			started := time.Now()
			io.WriteString(input, "stop\n")
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			var waitErr error
			select {
			case waitErr = <-done:
			case <-time.After(budget + 500*time.Millisecond):
				cmd.Process.Kill()
				<-done
				t.Fatalf("process exceeded budget %v + scheduling tolerance 500ms", budget)
			}
			elapsed := time.Since(started)
			t.Logf("toolchain=%s OS=%s budget=%v scheduling_tolerance=500ms elapsed=%v overrun=%v", runtime.Version(), runtime.GOOS, budget, elapsed, max(elapsed-budget, 0))
			if mode != "cancel" && elapsed < budget-100*time.Millisecond {
				t.Fatalf("stalled process exited before graceful cutoff: %v", elapsed)
			}
			want := 1
			if mode == "cancel" {
				want = 0
			}
			if cmd.ProcessState.ExitCode() != want {
				t.Fatalf("exit %d want %d: %v\n%s", cmd.ProcessState.ExitCode(), want, waitErr, logs.String())
			}
			if elapsed > budget+500*time.Millisecond {
				t.Fatalf("elapsed %v", elapsed)
			}
			if mode == "stderr" || mode == "complete" {
				return
			}
			if !strings.Contains(logs.String(), `"msg":"stop_requested"`) {
				t.Fatal(logs.String())
			}
			if mode == "cancel" {
				if !strings.Contains(logs.String(), `"msg":"shutdown_complete"`) {
					t.Fatal(logs.String())
				}
			} else if !strings.Contains(logs.String(), `"msg":"shutdown_timeout"`) || strings.Contains(logs.String(), `"msg":"shutdown_complete"`) {
				t.Fatal(logs.String())
			}
		})
	}
}

// lateListener reports its close without allocating a socket.
type lateListener struct{ closed chan struct{} }

func (l *lateListener) Accept() (net.Conn, error) { return nil, net.ErrClosed }
func (l *lateListener) Close() error              { close(l.closed); return nil }
func (l *lateListener) Addr() net.Addr            { return &net.TCPAddr{} }

func TestLateStartupResultCannotServe(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered, release := make(chan struct{}), make(chan struct{})
	ln := &lateListener{closed: make(chan struct{})}
	logs := &syncBuffer{}
	done := make(chan int, 1)
	path := writeConfig(t, plaintextConfig(12345, "console: {enabled: false}\nshutdown: {timeout_ms: 1000}\n"))
	go func() {
		done <- Serve(ctx, Options{ConfigFlag: path, ConfigFlagSet: true, Stderr: logs, listener: func(string, string) (net.Listener, error) { close(entered); <-release; return ln, nil }})
	}()
	<-entered
	cancel()
	if code := <-done; code != ExitFailure {
		t.Fatalf("exit %d", code)
	}
	close(release)
	select {
	case <-ln.closed:
	case <-time.After(time.Second):
		t.Fatal("late listener not closed")
	}
	if hasMsg(t, logs.String(), "ready") || hasMsg(t, logs.String(), "listening") {
		t.Fatal(logs.String())
	}
}

// heldListener stalls the real Close or Serve join path without sockets.
type heldListener struct {
	accepted chan struct{}
	mode     string
	closed   chan struct{}
	once     sync.Once
}

func (l *heldListener) Accept() (net.Conn, error) {
	close(l.accepted)
	<-l.closed
	if l.mode == "join" {
		select {}
	}
	return nil, net.ErrClosed
}
func (l *heldListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	if l.mode == "cleanup" {
		select {}
	}
	return nil
}
func (l *heldListener) Addr() net.Addr { return &net.TCPAddr{} }
