// Package config loads and validates the ricevanta-server configuration of
// docs/specs/server-runtime.md section 3: one strictly decoded YAML file plus
// a closed list of environment overrides, checked against the bounds of
// schemas/server/config/v1/config.schema.json with the standard library.
//
// Errors name the configuration key or environment variable and the rule,
// never the offending value, so they are safe to log.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"go.yaml.in/yaml/v3"
)

// DefaultPath is the configuration file used when neither --config nor
// RICEVANTA_SERVER_CONFIG selects one.
const DefaultPath = "/etc/ricevanta/server.yaml"

// SchemaID is the only accepted value of the schema key.
const SchemaID = "ricevanta-server-config-v1"

// MaxFileBytes bounds the configuration file.
const MaxFileBytes = 65536

// Error codes.
const (
	CodeInvalid                   = "config_invalid"
	CodePlaintextRequiresLoopback = "plaintext_requires_loopback"
	CodeUnknownEnvironment        = "unknown_environment_variable"
	CodeKeyFileRejected           = "key_file_rejected"
	CodeCertificateFileRejected   = "certificate_file_rejected"
)

// Error is a configuration error. Field names a key path or an environment
// variable; Reason states the rule. Neither carries a configured value.
type Error struct {
	Code   string
	Field  string
	Reason string
}

func (e *Error) Error() string {
	if e.Field == "" {
		return e.Code + ": " + e.Reason
	}
	return e.Code + ": " + e.Field + ": " + e.Reason
}

func invalid(field, format string, args ...any) error {
	return &Error{Code: CodeInvalid, Field: field, Reason: fmt.Sprintf(format, args...)}
}

// Roles of BE-03, in the order the schema lists them.
var Roles = []string{"api", "agent", "device", "radius", "jobs"}

// Config is the effective configuration after defaults and overrides.
type Config struct {
	Schema   string
	Roles    []string
	Listen   Listen
	Console  Console
	Log      Log
	HTTP     HTTP
	Shutdown Shutdown
}

// Listen holds the listeners; only api exists in v1.
type Listen struct {
	API *Listener
}

// Listener is one listener's address and transport security.
type Listener struct {
	Address string
	TLS     TLS
}

// TLS selects PEM files or, on loopback only, plaintext.
type TLS struct {
	Mode            string
	CertificateFile string
	KeyFile         string
}

// Console controls the embedded console.
type Console struct{ Enabled bool }

// Log sets the minimum log level.
type Log struct{ Level string }

// HTTP holds the server-wide HTTP bounds.
type HTTP struct {
	ReadHeaderTimeoutMS int
	IdleTimeoutMS       int
	MaxHeaderBytes      int
}

// Shutdown bounds graceful shutdown.
type Shutdown struct{ TimeoutMS int }

// ReadHeaderTimeout returns http.read_header_timeout_ms as a duration.
func (h HTTP) ReadHeaderTimeout() time.Duration {
	return time.Duration(h.ReadHeaderTimeoutMS) * time.Millisecond
}

// IdleTimeout returns http.idle_timeout_ms as a duration.
func (h HTTP) IdleTimeout() time.Duration { return time.Duration(h.IdleTimeoutMS) * time.Millisecond }

// Timeout returns shutdown.timeout_ms as a duration.
func (s Shutdown) Timeout() time.Duration { return time.Duration(s.TimeoutMS) * time.Millisecond }

// HasRole reports whether the configuration lists role.
func (c Config) HasRole(role string) bool {
	for _, r := range c.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// raw mirrors the YAML document; pointers record presence for defaults.
type raw struct {
	Schema   *string      `yaml:"schema"`
	Roles    *[]string    `yaml:"roles"`
	Listen   *rawListen   `yaml:"listen"`
	Console  *rawConsole  `yaml:"console"`
	Log      *rawLog      `yaml:"log"`
	HTTP     *rawHTTP     `yaml:"http"`
	Shutdown *rawShutdown `yaml:"shutdown"`
}

type rawListen struct {
	API *rawListener `yaml:"api"`
}

type rawListener struct {
	Address *string `yaml:"address"`
	TLS     *rawTLS `yaml:"tls"`
}

type rawTLS struct {
	Mode            *string `yaml:"mode"`
	CertificateFile *string `yaml:"certificate_file"`
	KeyFile         *string `yaml:"key_file"`
}

type rawConsole struct {
	Enabled *bool `yaml:"enabled"`
}

type rawLog struct {
	Level *string `yaml:"level"`
}

type rawHTTP struct {
	ReadHeaderTimeoutMS *int `yaml:"read_header_timeout_ms"`
	IdleTimeoutMS       *int `yaml:"idle_timeout_ms"`
	MaxHeaderBytes      *int `yaml:"max_header_bytes"`
}

type rawShutdown struct {
	TimeoutMS *int `yaml:"timeout_ms"`
}

// ResolvePath selects the configuration file: the --config flag when given,
// else RICEVANTA_SERVER_CONFIG when set, else DefaultPath.
func ResolvePath(flagValue string, flagSet bool, env func(string) (string, bool)) (string, error) {
	if flagSet {
		if flagValue == "" {
			return "", invalid("--config", "must not be empty")
		}
		return flagValue, nil
	}
	if v, ok := env(EnvConfig); ok {
		if v == "" {
			return "", invalid(EnvConfig, "must not be empty")
		}
		return v, nil
	}
	return DefaultPath, nil
}

// Load reads the file at path, applies the environment overrides that env
// returns and validates the result. It opens no file other than path.
func Load(path string, env func(string) (string, bool)) (Config, error) {
	data, err := readConfigFile(path)
	if err != nil {
		return Config{}, err
	}
	return parse(data, env)
}

// Parse decodes and validates a configuration document held in memory.
func Parse(data []byte, env func(string) (string, bool)) (Config, error) {
	if len(data) > MaxFileBytes {
		return Config{}, invalid("", "file exceeds %d bytes", MaxFileBytes)
	}
	return parse(data, env)
}

func readConfigFile(path string) ([]byte, error) {
	f, err := openRegular(path)
	if err != nil {
		return nil, invalid("", "cannot open the configuration file: %v", sanitizePathError(err))
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, MaxFileBytes+1))
	if err != nil {
		return nil, invalid("", "cannot read the configuration file")
	}
	if len(data) > MaxFileBytes {
		return nil, invalid("", "file exceeds %d bytes", MaxFileBytes)
	}
	return data, nil
}

func parse(data []byte, env func(string) (string, bool)) (Config, error) {
	if !utf8.Valid(data) {
		return Config{}, invalid("", "file is not valid UTF-8")
	}
	if bytes.HasPrefix(data, []byte("\xef\xbb\xbf")) {
		return Config{}, invalid("", "file starts with a byte order mark")
	}
	if err := prepass(data); err != nil {
		return Config{}, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var r raw
	if err := dec.Decode(&r); err != nil {
		return Config{}, sanitizeYAML(err)
	}
	if err := applyEnv(&r, env); err != nil {
		return Config{}, err
	}
	return validate(r)
}

var (
	reYAMLLine     = regexp.MustCompile(`^yaml: line (\d+):`)
	reTypeLine     = regexp.MustCompile(`^line (\d+): `)
	reAlreadyDef   = regexp.MustCompile(`already defined at line (\d+)$`)
	reAlreadySet   = regexp.MustCompile(`already set in type`)
	reFieldMissing = regexp.MustCompile(`not found in type`)
)

// sanitizeYAML maps yaml.v3 errors to messages without document content.
func sanitizeYAML(err error) error {
	var te *yaml.TypeError
	if errors.As(err, &te) && len(te.Errors) > 0 {
		msg := te.Errors[0]
		line := ""
		if m := reTypeLine.FindStringSubmatch(msg); m != nil {
			line = "line " + m[1] + ": "
		}
		switch {
		case reAlreadyDef.MatchString(msg):
			m := reAlreadyDef.FindStringSubmatch(msg)
			return invalid("", "%smapping key already defined at line %s", line, m[1])
		case reAlreadySet.MatchString(msg):
			return invalid("", "%sfield already set", line)
		case reFieldMissing.MatchString(msg):
			return invalid("", "%sunknown key", line)
		}
		return invalid("", "%svalue has the wrong type", line)
	}
	if m := reYAMLLine.FindStringSubmatch(err.Error()); m != nil {
		return invalid("", "YAML syntax error at line %s", m[1])
	}
	return invalid("", "YAML syntax error")
}

func validate(r raw) (Config, error) {
	var c Config
	if r.Schema == nil {
		return c, invalid("schema", "is required")
	}
	if *r.Schema != SchemaID {
		return c, invalid("schema", "must be %s", SchemaID)
	}
	c.Schema = *r.Schema
	if r.Roles == nil {
		return c, invalid("roles", "is required")
	}
	roles, err := validateRoles(*r.Roles, "roles")
	if err != nil {
		return c, err
	}
	c.Roles = roles

	if r.Listen != nil && r.Listen.API != nil {
		l, err := validateListener(*r.Listen.API, "listen.api")
		if err != nil {
			return c, err
		}
		c.Listen.API = &l
	}
	if c.HasRole("api") && c.Listen.API == nil {
		return c, invalid("listen.api", "is required when roles lists api")
	}

	c.Console.Enabled = true
	if r.Console != nil && r.Console.Enabled != nil {
		c.Console.Enabled = *r.Console.Enabled
	}
	c.Log.Level = "info"
	if r.Log != nil && r.Log.Level != nil {
		c.Log.Level = *r.Log.Level
	}
	switch c.Log.Level {
	case "error", "warn", "info", "debug":
	default:
		return c, invalid("log.level", "must be error, warn, info or debug")
	}
	c.HTTP = HTTP{ReadHeaderTimeoutMS: 10000, IdleTimeoutMS: 60000, MaxHeaderBytes: 65536}
	c.Shutdown.TimeoutMS = 20000
	if r.HTTP != nil {
		if err := bounded(r.HTTP.ReadHeaderTimeoutMS, &c.HTTP.ReadHeaderTimeoutMS, "http.read_header_timeout_ms", 1000, 60000); err != nil {
			return c, err
		}
		if err := bounded(r.HTTP.IdleTimeoutMS, &c.HTTP.IdleTimeoutMS, "http.idle_timeout_ms", 1000, 600000); err != nil {
			return c, err
		}
		if err := bounded(r.HTTP.MaxHeaderBytes, &c.HTTP.MaxHeaderBytes, "http.max_header_bytes", 4096, 1048576); err != nil {
			return c, err
		}
	}
	if r.Shutdown != nil {
		if err := bounded(r.Shutdown.TimeoutMS, &c.Shutdown.TimeoutMS, "shutdown.timeout_ms", 1000, 120000); err != nil {
			return c, err
		}
	}
	return c, nil
}

func bounded(v *int, dst *int, field string, lo, hi int) error {
	if v == nil {
		return nil
	}
	if *v < lo || *v > hi {
		return invalid(field, "must be between %d and %d", lo, hi)
	}
	*dst = *v
	return nil
}

func validateRoles(roles []string, field string) ([]string, error) {
	if len(roles) == 0 {
		return nil, invalid(field, "must list at least one role")
	}
	if len(roles) > len(Roles) {
		return nil, invalid(field, "lists more than %d roles", len(Roles))
	}
	seen := map[string]bool{}
	for _, r := range roles {
		known := false
		for _, k := range Roles {
			known = known || r == k
		}
		if !known {
			return nil, invalid(field, "unknown role; roles are api, agent, device, radius and jobs")
		}
		if seen[r] {
			return nil, invalid(field, "duplicate role")
		}
		seen[r] = true
	}
	return append([]string(nil), roles...), nil
}

func validateListener(r rawListener, field string) (Listener, error) {
	var l Listener
	if r.Address == nil {
		return l, invalid(field+".address", "is required")
	}
	host, err := ParseAddress(*r.Address)
	if err != nil {
		return l, invalid(field+".address", "%v", err)
	}
	l.Address = *r.Address
	if r.TLS == nil || r.TLS.Mode == nil {
		return l, invalid(field+".tls.mode", "is required whenever %s is present", field)
	}
	l.TLS.Mode = *r.TLS.Mode
	var certFile, keyFile *string
	if r.TLS != nil {
		certFile, keyFile = r.TLS.CertificateFile, r.TLS.KeyFile
	}
	switch l.TLS.Mode {
	case "file":
		if certFile == nil {
			return l, invalid(field+".tls.certificate_file", "is required when tls.mode is file")
		}
		if keyFile == nil {
			return l, invalid(field+".tls.key_file", "is required when tls.mode is file")
		}
		if !absolutePath(*certFile) {
			return l, invalid(field+".tls.certificate_file", "must be an absolute path of 2 to 1024 characters without NUL")
		}
		if !absolutePath(*keyFile) {
			return l, invalid(field+".tls.key_file", "must be an absolute path of 2 to 1024 characters without NUL")
		}
		l.TLS.CertificateFile, l.TLS.KeyFile = *certFile, *keyFile
	case "none":
		if certFile != nil || keyFile != nil {
			return l, invalid(field+".tls", "certificate_file and key_file are not allowed when tls.mode is none")
		}
		if !host.IsValid() || !host.Unmap().IsLoopback() {
			return l, &Error{Code: CodePlaintextRequiresLoopback, Field: field + ".address",
				Reason: "tls.mode none requires a loopback address"}
		}
	default:
		return l, invalid(field+".tls.mode", "must be file or none")
	}
	return l, nil
}

func absolutePath(p string) bool {
	n := utf8.RuneCountInString(p)
	return utf8.ValidString(p) && n >= 2 && n <= 1024 && p[0] == '/' && !strings.ContainsRune(p, 0)
}

var (
	reIPv4Octet = `(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])`
	reIPv4      = regexp.MustCompile(`\A` + reIPv4Octet + `(?:\.` + reIPv4Octet + `){3}\z`)
	reIPv6Chars = regexp.MustCompile(`\A[0-9A-Fa-f:.]+\z`)
	rePort      = regexp.MustCompile(`\A[1-9][0-9]{0,4}\z`)
)

// ParseAddress checks a listener address: host:port where host is empty, an
// IPv4 literal without leading zeros or a bracketed IPv6 literal without a
// zone, and port is 1 to 65535 without leading zeros. It returns the host
// address, or the zero Addr for an empty host.
func ParseAddress(s string) (netip.Addr, error) {
	if len(s) > 128 || !utf8.ValidString(s) {
		return netip.Addr{}, errors.New("must be host:port of at most 128 characters")
	}
	i := strings.LastIndexByte(s, ':')
	if i < 0 {
		return netip.Addr{}, errors.New("must be host:port")
	}
	host, port := s[:i], s[i+1:]
	if !rePort.MatchString(port) {
		return netip.Addr{}, errors.New("port must be 1 to 65535")
	}
	if n, _ := strconv.Atoi(port); n > 65535 {
		return netip.Addr{}, errors.New("port must be 1 to 65535")
	}
	switch {
	case host == "":
		return netip.Addr{}, nil
	case strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]"):
		inner := host[1 : len(host)-1]
		if !reIPv6Chars.MatchString(inner) {
			return netip.Addr{}, errors.New("host must be an IPv4 literal or a bracketed IPv6 literal")
		}
		a, err := netip.ParseAddr(inner)
		if err != nil || !a.Is6() || a.Zone() != "" {
			return netip.Addr{}, errors.New("bracketed host must be an IPv6 literal")
		}
		return a, nil
	case reIPv4.MatchString(host):
		a, err := netip.ParseAddr(host)
		if err != nil || !a.Is4() {
			return netip.Addr{}, errors.New("host must be an IPv4 literal or a bracketed IPv6 literal")
		}
		return a, nil
	}
	return netip.Addr{}, errors.New("host must be an IPv4 literal or a bracketed IPv6 literal")
}

// JSON returns the effective configuration as JSON with sorted keys. Key
// paths appear, file contents never do.
func (c Config) JSON() []byte {
	doc := map[string]any{
		"schema":   c.Schema,
		"roles":    c.Roles,
		"console":  map[string]any{"enabled": c.Console.Enabled},
		"log":      map[string]any{"level": c.Log.Level},
		"http":     map[string]any{"read_header_timeout_ms": c.HTTP.ReadHeaderTimeoutMS, "idle_timeout_ms": c.HTTP.IdleTimeoutMS, "max_header_bytes": c.HTTP.MaxHeaderBytes},
		"shutdown": map[string]any{"timeout_ms": c.Shutdown.TimeoutMS},
	}
	if c.Roles == nil {
		doc["roles"] = []string{}
	}
	if c.Listen.API != nil {
		tls := map[string]any{"mode": c.Listen.API.TLS.Mode}
		if c.Listen.API.TLS.CertificateFile != "" {
			tls["certificate_file"] = c.Listen.API.TLS.CertificateFile
		}
		if c.Listen.API.TLS.KeyFile != "" {
			tls["key_file"] = c.Listen.API.TLS.KeyFile
		}
		doc["listen"] = map[string]any{"api": map[string]any{"address": c.Listen.API.Address, "tls": tls}}
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(doc); err != nil {
		panic(err) // maps of strings, ints and bools always encode
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
}
