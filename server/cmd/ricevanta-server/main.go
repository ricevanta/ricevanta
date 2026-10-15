// Command ricevanta-server is the Ricevanta server executable
// (docs/specs/server-runtime.md). It parses the command line, dispatches to
// the runtime and returns its exit code; it holds no other logic.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/ricevanta/ricevanta/server/internal/buildinfo"
	"github.com/ricevanta/ricevanta/server/internal/platform/runtime"
)

const usage = `usage:
  ricevanta-server --version
  ricevanta-server version [--json]
  ricevanta-server serve [--config PATH]
  ricevanta-server check-config [--config PATH]
  ricevanta-server console-manifest
`

// Exit codes of docs/specs/server-runtime.md section 2.
const (
	exitOK    = runtime.ExitOK
	exitUsage = runtime.ExitConfig
)

func main() {
	os.Exit(dispatch(os.Args[1:], os.Stdout, os.Stderr))
}

func usageError(stderr io.Writer, format string, args ...any) int {
	fmt.Fprintf(stderr, "ricevanta-server: "+format+"\n", args...)
	io.WriteString(stderr, usage)
	return exitUsage
}

func dispatch(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		return usageError(stderr, "missing command")
	}
	switch args[0] {
	case "--version", "-version":
		if len(args) != 1 {
			return usageError(stderr, "--version takes no arguments")
		}
		fmt.Fprintln(stdout, buildinfo.Current().Line())
		return exitOK
	case "version":
		fs := newFlagSet("version", stderr)
		asJSON := fs.Bool("json", false, "print the identity as JSON")
		if code, ok := parse(fs, args[1:], stderr); !ok {
			return code
		}
		if *asJSON {
			fmt.Fprintf(stdout, "%s\n", buildinfo.Current().JSON())
		} else {
			fmt.Fprintln(stdout, buildinfo.Current().Line())
		}
		return exitOK
	case "serve", "check-config":
		fs := newFlagSet(args[0], stderr)
		path := fs.String("config", "", "configuration file")
		if code, ok := parse(fs, args[1:], stderr); !ok {
			return code
		}
		set := false
		fs.Visit(func(f *flag.Flag) { set = set || f.Name == "config" })
		o := runtime.Options{ConfigFlag: *path, ConfigFlagSet: set, Environ: os.Environ(), Stdout: stdout, Stderr: stderr}
		if args[0] == "check-config" {
			return runtime.CheckConfig(o)
		}
		return runtime.Serve(context.Background(), o)
	case "console-manifest":
		if code, ok := parse(newFlagSet(args[0], stderr), args[1:], stderr); !ok {
			return code
		}
		return runtime.ConsoleManifest(runtime.Options{Stdout: stdout, Stderr: stderr})
	case "migrate":
		fmt.Fprintln(stderr, "ricevanta-server: migrate is blocked: it waits for the database and journal slices")
		return exitUsage
	}
	return usageError(stderr, "unknown command %q", args[0])
}

func newFlagSet(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	return fs
}

// parse parses flags and rejects positional arguments.
func parse(fs *flag.FlagSet, args []string, stderr io.Writer) (int, bool) {
	if err := fs.Parse(args); err != nil {
		return usageError(stderr, "%s: %v", fs.Name(), err), false
	}
	if fs.NArg() != 0 {
		return usageError(stderr, "%s: unexpected argument %q", fs.Name(), fs.Arg(0)), false
	}
	return 0, true
}
