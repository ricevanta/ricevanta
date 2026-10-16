// Package runtime runs ricevanta-server (docs/specs/server-runtime.md
// section 4): configuration, role admission, console verification, TLS
// material, the api listener, readiness, signals and bounded shutdown.
package runtime

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"io/fs"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ricevanta/ricevanta/server/internal/buildinfo"
	"github.com/ricevanta/ricevanta/server/internal/platform/config"
	"github.com/ricevanta/ricevanta/server/internal/platform/health"
	"github.com/ricevanta/ricevanta/server/internal/transport/console"
)

// Exit codes of spec section 2.
const (
	ExitOK      = 0 // success
	ExitFailure = 1 // runtime failure or a missed stop deadline, including startup
	ExitConfig  = 2 // command line or configuration error, blocked role
	ExitStartup = 3 // console verification, TLS material, listener bind
)

// Options carries one command's inputs. The unexported fields are set only
// by this package's tests; the command line never reaches them and no
// environment variable sets them.
type Options struct {
	configLoader  func() (config.Config, error)
	tlsLoader     func(config.TLS) (*tls.Config, error)
	listener      func(string, string) (net.Listener, error)
	ConfigFlag    string // value of --config
	ConfigFlagSet bool   // whether --config was given
	Environ       []string
	Stdout        io.Writer
	Stderr        io.Writer

	consoleSource func() (fs.FS, []byte, bool)
	identity      *buildinfo.Identity
	wrap          func(http.Handler) http.Handler
	atStep        func(step string)
	// ProcessExit installs the executable watchdog; nil keeps library calls nonfatal.
	ProcessExit func(int)
	ready       chan<- string
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

// Serve runs startup in one serial worker, independently of stop handling.
// ProcessExit is installed only by the executable. Library calls never exit
// their caller; the controller still returns a bounded failure result.
func Serve(parent context.Context, o Options) int {
	stopCtx, stop := signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
	defer stop()
	c := newStopController(parent)
	stopDone := stopCtx.Done()
	c.cancelled = func() bool {
		select {
		case <-stopDone:
			return true
		default:
			return false
		}
	}
	level := new(slog.LevelVar)
	logger := slog.New(slog.NewJSONHandler(o.Stderr, &slog.HandlerOptions{Level: level}))
	finished := make(chan struct{})
	defer close(finished)
	go func() {
		select {
		case <-stopCtx.Done():
			c.observeCancellation()
			select {
			case <-parent.Done():
				c.observeCancellation()
			case <-finished:
			}
		case <-finished:
			return
		}
	}()
	extra := make(chan os.Signal, 8)
	signal.Notify(extra, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(extra)
	go func() {
		for {
			select {
			case <-extra:
				c.countSignal()
			case <-finished:
				return
			}
		}
	}()
	// This watchdog never waits for logging, cleanup, joins or a Serve result.
	go func() {
		select {
		case <-c.stopped:
		case <-finished:
			c.mu.Lock()
			stopped := !c.first.IsZero()
			c.mu.Unlock()
			if !stopped {
				return
			}
		}
		timer := time.NewTimer(time.Until(c.deadline))
		defer timer.Stop()
		if o.ProcessExit != nil {
			<-timer.C
			o.ProcessExit(ExitFailure)
		} else {
			select {
			case <-timer.C:
			case <-finished:
			}
		}
	}()
	worker := make(chan int, 1)
	go func() {
		code := ExitFailure
		defer func() {
			if recover() != nil {
				c.mu.Lock()
				c.failure = ExitFailure
				c.mu.Unlock()
			}
			worker <- code
		}()
		code = startup(o, c, logger, level)
	}()
	select {
	case code := <-worker:
		if !c.isStopped() {
			return code
		}
		worker <- code
	case <-c.stopped:
	}
	c.mu.Lock()
	cutoff, deadline, registry, srv, ln := c.deadline.Add(-100*time.Millisecond), c.deadline, c.registry, c.server, c.listener
	c.mu.Unlock()
	if registry != nil {
		registry.SetAll(health.Stopping)
	}
	// One writer and a bounded terminal slot. A blocked sink cannot block the
	// controller, and repeated stops cannot spawn more writers.
	terminal := make(chan bool, 1)
	logged := make(chan struct{})
	go func() {
		logger.Log(context.Background(), max(slog.LevelInfo, level.Level()), "stop_requested", "step", c.stepName())
		timeout := <-terminal
		if timeout {
			logger.Error("shutdown_timeout", "repeated_stop_requests", c.repeatCount())
		} else {
			logger.Log(context.Background(), max(slog.LevelInfo, level.Level()), "shutdown_complete", "repeated_stop_requests", c.repeatCount())
		}
		close(logged)
	}()
	cleaned := make(chan struct{})
	go func() {
		defer close(cleaned)
		if ln != nil {
			ln.Close()
		}
		if srv != nil {
			ctx, cancel := context.WithDeadline(context.Background(), cutoff)
			defer cancel()
			_ = srv.Shutdown(ctx)
		}
	}()
	timer := time.NewTimer(time.Until(cutoff))
	defer timer.Stop()
	pendingWorker, pendingCleanup := worker, cleaned
wait:
	for pendingWorker != nil || pendingCleanup != nil {
		select {
		case <-pendingWorker:
			pendingWorker = nil
		case <-pendingCleanup:
			pendingCleanup = nil
		case <-timer.C:
			break wait
		}
	}
	// Completion at the cutoff cannot turn a timeout into success.
	timeout := pendingWorker != nil || pendingCleanup != nil || !time.Now().Before(cutoff)
	result := c.finish(!timeout)
	terminal <- timeout
	if timeout && srv != nil {
		go srv.Close()
	}
	final := time.NewTimer(time.Until(deadline))
	defer final.Stop()
	select {
	case <-logged:
		return result
	case <-final.C:
		return ExitFailure
	}
}

func startup(o Options, c *stopController, logger *slog.Logger, level *slog.LevelVar) int {
	id := o.id()
	if c.isStopped() {
		return ExitOK
	}
	logger.Info("starting", "version", id.Version, "commit", id.Commit, "channel", id.Channel)
	fail := func(step string, code int, err error) int {
		if !c.commitFailure(code) {
			return ExitOK
		}
		logger.Error("startup_failed", "step", step, "error", err.Error())
		return code
	}
	stopped := func(step string) bool {
		c.mu.Lock()
		c.step = step
		c.mu.Unlock()
		if o.atStep != nil {
			o.atStep(step)
		}
		return c.isStopped()
	}
	if stopped("before_config") {
		return ExitOK
	}
	loader := o.configLoader
	if loader == nil {
		loader = func() (config.Config, error) { return loadConfig(o) }
	}
	cfg, err := loader()
	if err != nil {
		return fail("config", ExitConfig, err)
	}
	c.publish(cfg.Shutdown.Timeout())
	if stopped("config") {
		return ExitOK
	}
	level.Set(parseLevel(cfg.Log.Level))
	logger.Info("config_loaded", "roles", cfg.Roles, "console", cfg.Console.Enabled, "log_level", cfg.Log.Level)
	if c.isStopped() {
		return ExitOK
	}
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
			return fail("console", ExitStartup, &console.VerifyError{Code: console.CodeMissing, Reason: "this build embeds no console"})
		}
		if c.isStopped() {
			return ExitOK
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
		loader := o.tlsLoader
		if loader == nil {
			loader = loadTLS
		}
		if tlsConfig, err = loader(api.TLS); err != nil {
			return fail("tls", ExitStartup, err)
		}
	}
	if stopped("tls") {
		return ExitOK
	}
	listen := o.listener
	if listen == nil {
		listen = net.Listen
	}
	ln, err := listen("tcp", api.Address)
	if err != nil {
		return fail("listen", ExitStartup, err)
	}
	if !c.handoff(func() { c.listener = ln }) {
		ln.Close()
		return ExitOK
	}
	if stopped("listen") {
		return ExitOK
	}

	registry := health.NewRegistry(cfg.Roles)
	if !c.handoff(func() { c.registry = registry }) {
		return ExitOK
	}
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

	if !c.handoff(func() { c.server = srv }) {
		return ExitOK
	}
	served := make(chan error, 1)
	if !c.handoff(func() {
		go func() {
			if tlsConfig != nil {
				served <- srv.ServeTLS(ln, "", "")
			} else {
				served <- srv.Serve(ln)
			}
		}()
	}) {
		return ExitOK
	}
	logger.Info("listening", "role", "api", "address", ln.Addr().String(), "tls", tlsConfig != nil)
	if !stopped("serve") {
		if c.handoff(func() { registry.Set("api", health.Ready) }) {
			logger.Info("ready")
			if o.ready != nil {
				select {
				case o.ready <- ln.Addr().String():
				case <-c.stopped:
				}
			}
		}
	}
	select {
	case <-c.stopped:
	case err := <-served:
		if !c.isStopped() {
			_ = err
			c.commitFailure(ExitFailure)
			c.request()
		}
		served <- err
	}
	<-served
	return c.failureCode()
}
