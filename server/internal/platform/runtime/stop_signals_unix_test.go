//go:build unix

package runtime

import (
	"bufio"
	"bytes"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestRepeatedSignalsDoNotMoveProcessDeadline(t *testing.T) {
	cmd := exec.Command(buildStopProcessHelper(t), "-test.run=^TestStopProcessHelper$")
	cmd.Env = append(os.Environ(), "RICEVANTA_TEST_STOP_HELPER=tls")
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	output, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	cmd.Stderr = &logs
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	entered := make(chan string, 1)
	go func() { line, _ := bufio.NewReader(output).ReadString('\n'); entered <- line }()
	select {
	case line := <-entered:
		if line != "entered\n" {
			t.Fatalf("entry %q", line)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no entry")
	}
	started := time.Now()
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if err := cmd.Process.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(1400 * time.Millisecond):
		cmd.Process.Kill()
		<-done
		t.Fatal("repeated signal extended deadline")
	}
	elapsed := time.Since(started)
	t.Logf("budget=1s scheduling_tolerance=500ms elapsed=%v", elapsed)
	if cmd.ProcessState.ExitCode() != 1 || elapsed > 1500*time.Millisecond {
		t.Fatalf("exit %d elapsed %v", cmd.ProcessState.ExitCode(), elapsed)
	}
	if strings.Count(logs.String(), `"msg":"stop_requested"`) != 1 || strings.Count(logs.String(), `"msg":"shutdown_timeout"`) != 1 || !strings.Contains(logs.String(), `"repeated_stop_requests":1`) {
		t.Fatal(logs.String())
	}
}
