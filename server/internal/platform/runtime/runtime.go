// Package runtime runs ricevanta-server (docs/specs/server-runtime.md
// section 4): configuration, role admission, console verification, TLS
// material, the api listener, readiness, signals and bounded shutdown.
package runtime

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"

	"github.com/ricevanta/ricevanta/server/internal/buildinfo"
	"github.com/ricevanta/ricevanta/server/internal/platform/config"
	"github.com/ricevanta/ricevanta/server/internal/platform/health"
	"github.com/ricevanta/ricevanta/server/internal/transport/console"
)

// Exit codes of spec section 2.
const (
	ExitOK      = 0 // success
	ExitFailure = 1 // failure after ready, including a missed shutdown deadline
	ExitConfig  = 2 // command line or configuration error, blocked role
	ExitStartup = 3 // console verification, TLS material, listener bind
)

// Options carries one command's inputs. The unexported fields are set only
// by this package's tests; the command line never reaches them and no
// environment variable sets them.
type Options struct {
	ConfigFlag    string // value of --config
	ConfigFlagSet bool   // whether --config was given
	Environ       []string
	Stdout        io.Writer
	Stderr        io.Writer

	consoleSource func() (fs.FS, []byte, bool)
	identity      *buildinfo.Identity
	wrap          func(http.Handler) http.Handler
	atStep        func(step string)
	ready         chan<- string
}

func (o Options) source() func() (fs.FS, []byte, bool) {
	if o.consoleSource != nil {
		return o.consoleSource
	}
	return console.Embedded
}

func (o Options) id() buildinfo.Identity {
	if o.identity != nil {
		return *o.identity
	}
	return buildinfo.Current()
}

// loadConfig checks the environment prefix, resolves the file and loads it.
func loadConfig(o Options) (config.Config, error) {
	if err := config.CheckEnviron(o.Environ); err != nil {
		return config.Config{}, err
	}
	lookup := config.LookupFrom(o.Environ)
	path, err := config.ResolvePath(o.ConfigFlag, o.ConfigFlagSet, lookup)
	if err != nil {
		return config.Config{}, err
	}
	return config.Load(path, lookup)
}

// CheckConfig validates the configuration, applies role admission and prints
// the effective configuration as sorted-key JSON. It opens no TLS file.
func CheckConfig(o Options) int {
	cfg, err := loadConfig(o)
	if err == nil {
		err = Admit(cfg.Roles)
	}
	if err != nil {
		fmt.Fprintf(o.Stderr, "ricevanta-server: check-config: %v\n", err)
		return ExitConfig
	}
	fmt.Fprintf(o.Stdout, "%s\n", cfg.JSON())
	return ExitOK
}

// ConsoleManifest verifies the embedded console and prints its manifest.json
// bytes unchanged.
func ConsoleManifest(o Options) int {
	dist, manifest, ok := o.source()()
	if !ok {
		fmt.Fprintf(o.Stderr, "ricevanta-server: console-manifest: %s: this build embeds no console\n", console.CodeMissing)
		return ExitStartup
	}
	tree, err := console.Verify(dist, manifest, o.id())
	if err != nil {
		fmt.Fprintf(o.Stderr, "ricevanta-server: console-manifest: %v\n", err)
		return ExitStartup
	}
	o.Stdout.Write(tree.Manifest())
	return ExitOK
}

// loadTLS reads the certificate chain and the private key, the key under
// the key-file rule of spec section 3.
func loadTLS(t config.TLS) (*tls.Config, error) {
	keyPEM, err := config.ReadKeyFile(t.KeyFile)
	if err != nil {
		return nil, err
	}
	certPEM, err := config.ReadCertificateFile(t.CertificateFile)
	if err != nil {
		return nil, err
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		// The parser's message names no key material.
		return nil, fmt.Errorf("tls_material_invalid: %w", err)
	}
	return &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}, nil
}

// Serve runs the server until parent is cancelled or SIGTERM or SIGINT
// arrives, and returns the exit code. The stop sources are registered before
// configuration loads, and a stop before ready ends startup at the next step
// boundary with exit 0 after closing what was opened (spec section 4).
func Serve(parent context.Context, o Options) (code int) {
	level := new(slog.LevelVar) // info until the configuration sets it
	logger := slog.New(slog.NewJSONHandler(o.Stderr, &slog.HandlerOptions{Level: level}))
	defer func() {
		// A panic outside a handler ends the process with exit 1; the
		// JSON handler writes synchronously, so earlier lines are flushed.
		if recover() != nil {
			code = ExitFailure
		}
	}()

	stopCtx, stop := signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
	defer stop()
	// A second channel counts stop requests; those after the first are
	// counted and otherwise ignored.
	var signals atomic.Int64
	extra := make(chan os.Signal, 8)
	signal.Notify(extra, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(extra)
	counted := make(chan struct{})
	defer close(counted)
	go func() {
		for {
			select {
			case <-extra:
				signals.Add(1)
			case <-counted:
				return
			}
		}
	}()
	repeated := func() int64 { return max(signals.Load()-1, 0) }

	id := o.id()
	logger.Info("starting", "version", id.Version, "commit", id.Commit, "channel", id.Channel)
	fail := func(step string, code int, err error) int {
		logger.Error("startup_failed", "step", step, "error", err.Error())
		return code
	}
	// stopped reports whether a stop arrived by the boundary after step; if
	// so the caller has closed what it opened and startup ends with exit 0.
	stopped := func(step string) bool {
		if o.atStep != nil {
			o.atStep(step)
		}
		if stopCtx.Err() == nil {
			return false
		}
		logger.Info("stop_requested", "step", step)
		logger.Info("shutdown_complete", "repeated_stop_requests", repeated())
		return true
	}

	cfg, err := loadConfig(o)
	if err != nil {
		return fail("config", ExitConfig, err)
	}
	// Checked before the configured level applies, so the stop is logged
	// at info whatever level the configuration names.
	if stopped("config") {
		return ExitOK
	}
	level.Set(parseLevel(cfg.Log.Level))
	logger.Info("config_loaded", "roles", cfg.Roles, "console", cfg.Console.Enabled, "log_level", cfg.Log.Level)
	if err := Admit(cfg.Roles); err != nil {
		return fail("roles", ExitConfig, err)
	}
	if stopped("roles") {
		return ExitOK
	}

	var tree *console.Tree
	if cfg.Console.Enabled {
		dist, manifest, ok := o.source()()
		if !ok {
			return fail("console", ExitStartup, &console.VerifyError{Code: console.CodeMissing, Reason: "this build embeds no console; build with -tags ricevanta_console or set console.enabled false"})
		}
		if tree, err = console.Verify(dist, manifest, id); err != nil {
			return fail("console", ExitStartup, err)
		}
		logger.Info("console_verified")
	}
	if stopped("console") {
		return ExitOK
	}

	api := cfg.Listen.API
	var tlsConfig *tls.Config
	if api.TLS.Mode == "file" {
		if tlsConfig, err = loadTLS(api.TLS); err != nil {
			return fail("tls", ExitStartup, err)
		}
	}
	if stopped("tls") {
		return ExitOK
	}
	ln, err := net.Listen("tcp", api.Address)
	if err != nil {
		var oe *net.OpError
		if errors.As(err, &oe) {
			err = oe.Err
		}
		return fail("listen", ExitStartup, err)
	}
	if stopped("listen") {
		ln.Close()
		return ExitOK
	}

	registry := health.NewRegistry(cfg.Roles)
	var root http.Handler = console.NewHandler(tree, registry.Healthz(), registry.Readyz())
	if o.wrap != nil {
		root = o.wrap(root)
	}
	srv := &http.Server{
		Handler:                      logRequests(logger, root),
		ReadHeaderTimeout:            cfg.HTTP.ReadHeaderTimeout(),
		IdleTimeout:                  cfg.HTTP.IdleTimeout(),
		MaxHeaderBytes:               cfg.HTTP.MaxHeaderBytes,
		DisableGeneralOptionsHandler: true,
		TLSConfig:                    tlsConfig,
		// On HTTP/2 a stream's write deadline only queues RST_STREAM behind
		// the connection's frame writer, which blocks with no deadline on a
		// client that stopped reading. WriteByteTimeout closes such a
		// connection once no byte could be written for the same 10 s bound.
		HTTP2: &http.HTTP2Config{WriteByteTimeout: console.WriteProgress},
		// net/http's own messages are free text outside the closed
		// event catalogue, so they are not written to the JSON log.
		ErrorLog: log.New(io.Discard, "", 0),
	}

	served := make(chan error, 1)
	go func() {
		if tlsConfig != nil {
			served <- srv.ServeTLS(ln, "", "")
		} else {
			served <- srv.Serve(ln)
		}
	}()
	logger.Info("listening", "role", "api", "address", ln.Addr().String(), "tls", tlsConfig != nil)

	result := ExitOK
	if o.atStep != nil {
		o.atStep("serve")
	}
	if stopCtx.Err() != nil {
		// A stop at the serve boundary, before ready, takes the drain
		// path below without ever reporting ready.
		logger.Info("stop_requested", "step", "serve")
	} else {
		registry.Set("api", health.Ready)
		logger.Info("ready")
		if o.ready != nil {
			o.ready <- ln.Addr().String()
		}
		select {
		case <-stopCtx.Done():
			logger.Info("stop_requested")
		case err := <-served:
			// The listener failed without a stop request.
			logger.Error("stop_requested", "reason", "listener_failed", "error", err.Error())
			served <- err
			result = ExitFailure
		}
	}

	registry.SetAll(health.Stopping)
	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.Shutdown.Timeout())
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("shutdown_timeout", "timeout_ms", cfg.Shutdown.TimeoutMS)
		srv.Close()
		<-served
		return ExitFailure
	}
	// Serve closes the listener when it returns. Waiting for it covers a
	// stop at the serve boundary, where Shutdown can run before Serve has
	// registered the listener and so cannot close it itself.
	<-served
	logger.Info("shutdown_complete", "repeated_stop_requests", repeated())
	return result
}
