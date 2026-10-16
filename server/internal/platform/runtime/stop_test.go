package runtime

import (
	"context"
	"crypto/tls"
	"io/fs"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/ricevanta/ricevanta/server/internal/platform/config"
)

func TestStopBudgetPublication(t *testing.T) {
	for i := 0; i < 100; i++ {
		c := newStopController(context.Background())
		done := make(chan struct{})
		go func() { c.publish(time.Second); close(done) }()
		c.request()
		<-done
		c.mu.Lock()
		budget := c.deadline.Sub(c.first)
		c.mu.Unlock()
		if budget != time.Second && budget != 20*time.Second {
			t.Fatalf("budget %v", budget)
		}
		first := c.deadline
		c.publish(2 * time.Second)
		c.request()
		if c.deadline != first || c.repeated != 1 {
			t.Fatalf("stop changed: %+v", c)
		}
	}
}

func TestBlockedStartupUsesOriginalStopBudget(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	entered, release := make(chan struct{}), make(chan struct{})
	defer close(release)
	logs := &syncBuffer{}
	done := make(chan int, 1)
	path := writeConfig(t, plaintextConfig(12345, "console: {enabled: false}\nshutdown: {timeout_ms: 1000}\n"))
	go func() {
		done <- Serve(ctx, Options{Stderr: logs, ConfigFlag: path, ConfigFlagSet: true, atStep: func(step string) {
			if step == "tls" {
				close(entered)
				<-release
			}
		}})
	}()
	<-entered
	started := time.Now()
	cancel()
	select {
	case code := <-done:
		if code != ExitFailure {
			t.Fatalf("exit %d", code)
		}
		if elapsed := time.Since(started); elapsed > 1500*time.Millisecond {
			t.Fatalf("elapsed %v", elapsed)
		}
		if !hasMsg(t, logs.String(), "shutdown_timeout") || hasMsg(t, logs.String(), "ready") {
			t.Fatal(logs.String())
		}
	case <-time.After(1500 * time.Millisecond):
		t.Fatal("blocked startup prevented stop")
	}
}

func TestFrozenBudgetAndTerminalFence(t *testing.T) {
	for _, budget := range []time.Duration{time.Second, 120 * time.Second} {
		for _, publishFirst := range []bool{false, true} {
			now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
			c := newStopController(context.Background())
			c.now = func() time.Time { return now }
			if publishFirst {
				c.publish(budget)
			}
			c.request()
			want := 20 * time.Second
			if publishFirst {
				want = budget
			}
			c.publish(budget)
			c.request()
			if c.deadline.Sub(c.first) != want {
				t.Fatalf("frozen budget %v want %v", c.deadline.Sub(c.first), want)
			}
			deadline := c.deadline
			if c.handoff(func() { t.Fatal("late readiness/resource accepted") }) {
				t.Fatal("late handoff")
			}
			now = deadline.Add(-100 * time.Millisecond)
			if c.finish(false) != ExitFailure {
				t.Fatal("pending work succeeded at cutoff")
			}
			now = deadline.Add(-time.Millisecond)
			if c.finish(true) != ExitFailure {
				t.Fatal("late completion changed timeout")
			}
			now = deadline
			if c.finish(true) != ExitFailure {
				t.Fatal("completion at deadline succeeded")
			}
			if c.deadline != deadline {
				t.Fatal("drain moved deadline")
			}
		}
	}
	for _, failure := range []int{ExitOK, ExitConfig, ExitStartup} {
		c := newStopController(context.Background())
		if failure != ExitOK {
			c.commitFailure(failure)
		}
		c.request()
		if c.commitFailure(ExitStartup) {
			t.Fatal("late failure committed")
		}
		if got := c.finish(true); got != failure {
			t.Fatalf("completion %d want %d", got, failure)
		}
	}
}

func TestBlockedStartupOperationsCancelBeforeCutoff(t *testing.T) {
	for _, step := range []string{"config", "console", "tls", "listen"} {
		t.Run(step, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			entered, release := make(chan struct{}), make(chan struct{})
			block := func() { close(entered); <-release }
			path := writeConfig(t, plaintextConfig(12345, "shutdown: {timeout_ms: 1000}\n"))
			logs := &syncBuffer{}
			o := Options{ConfigFlag: path, ConfigFlagSet: true, Stderr: logs}
			switch step {
			case "config":
				o.configLoader = func() (config.Config, error) { block(); return config.Config{}, context.Canceled }
			case "console":
				source := fixtureSource(t)
				o.consoleSource = func() (fs.FS, []byte, bool) {
					_, manifest, _ := source()
					return stalledFS{entered, release}, manifest, true
				}
			case "tls":
				o.configLoader = func() (config.Config, error) {
					cfg, err := loadConfig(o)
					cfg.Console.Enabled = false
					cfg.Listen.API.TLS.Mode = "file"
					return cfg, err
				}
				o.tlsLoader = func(config.TLS) (*tls.Config, error) { block(); return nil, context.Canceled }
			case "listen":
				o.configLoader = func() (config.Config, error) { cfg, err := loadConfig(o); cfg.Console.Enabled = false; return cfg, err }
				o.listener = func(string, string) (net.Listener, error) { block(); return nil, context.Canceled }
			}
			done := make(chan int, 1)
			go func() { done <- Serve(ctx, o) }()
			<-entered
			cancel()
			close(release)
			select {
			case code := <-done:
				if code != ExitOK {
					t.Fatalf("exit %d: %s", code, logs.String())
				}
			case <-time.After(time.Second):
				t.Fatal("cancellation did not finish")
			}
			if hasMsg(t, logs.String(), "startup_failed") || hasMsg(t, logs.String(), "ready") || !hasMsg(t, logs.String(), "shutdown_complete") {
				t.Fatal(logs.String())
			}
		})
	}
}

func TestRepeatedStopsKeepOneWorkerAndTerminalPair(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered := make(chan struct{})
	logs := &syncBuffer{}
	calls := 0
	path := writeConfig(t, plaintextConfig(12345, "console: {enabled: false}\nshutdown: {timeout_ms: 1000}\n"))
	done := make(chan int, 1)
	go func() {
		done <- Serve(ctx, Options{ConfigFlag: path, ConfigFlagSet: true, Stderr: logs, configLoader: func() (config.Config, error) {
			calls++
			close(entered)
			<-ctx.Done()
			return config.Config{}, context.Canceled
		}})
	}()
	<-entered
	for i := 0; i < 100; i++ {
		cancel()
	}
	if code := <-done; code != ExitOK {
		t.Fatalf("exit %d", code)
	}
	if calls != 1 {
		t.Fatalf("startup workers %d", calls)
	}
	for _, msg := range []string{"stop_requested", "shutdown_complete"} {
		if count := strings.Count(logs.String(), `"msg":"`+msg+`"`); count != 1 {
			t.Fatalf("%s records %d", msg, count)
		}
	}
	c := newStopController(context.Background())
	for i := 0; i < 100; i++ {
		c.countSignal()
	}
	if c.repeatCount() != 99 || c.deadline.Sub(c.first) != 20*time.Second {
		t.Fatalf("signals moved budget or lost count: %d", c.repeatCount())
	}
}

// stalledFS blocks inside Verify's first filesystem operation.
type stalledFS struct{ entered, release chan struct{} }

func (s stalledFS) Open(string) (fs.File, error) {
	close(s.entered)
	<-s.release
	return nil, context.Canceled
}

func TestParentAndSignalRequestsAreCountedOnce(t *testing.T) {
	for _, parentFirst := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		c := newStopController(ctx)
		if parentFirst {
			cancel()
			c.observeCancellation()
			c.countSignal()
		} else {
			c.countSignal()
			cancel()
			c.observeCancellation()
		}
		c.observeCancellation()
		if c.repeatCount() != 1 {
			t.Fatalf("parentFirst=%v repeats=%d", parentFirst, c.repeatCount())
		}
	}
}
