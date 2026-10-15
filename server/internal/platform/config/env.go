package config

import (
	"strings"
	"unicode/utf8"
)

// The closed list of environment variables (spec section 3).
const (
	EnvPrefix           = "RICEVANTA_SERVER_"
	EnvConfig           = "RICEVANTA_SERVER_CONFIG"
	EnvRoles            = "RICEVANTA_SERVER_ROLES"
	EnvListenAPIAddress = "RICEVANTA_SERVER_LISTEN_API_ADDRESS"
	EnvListenAPITLSMode = "RICEVANTA_SERVER_LISTEN_API_TLS_MODE"
	EnvListenAPITLSCert = "RICEVANTA_SERVER_LISTEN_API_TLS_CERTIFICATE_FILE"
	EnvListenAPITLSKey  = "RICEVANTA_SERVER_LISTEN_API_TLS_KEY_FILE"
	EnvConsoleEnabled   = "RICEVANTA_SERVER_CONSOLE_ENABLED"
	EnvLogLevel         = "RICEVANTA_SERVER_LOG_LEVEL"
)

var knownEnv = map[string]bool{
	EnvConfig: true, EnvRoles: true, EnvListenAPIAddress: true, EnvListenAPITLSMode: true,
	EnvListenAPITLSCert: true, EnvListenAPITLSKey: true, EnvConsoleEnabled: true, EnvLogLevel: true,
}

// CheckEnviron rejects every variable whose name starts with the
// RICEVANTA_SERVER_ prefix, compared case-insensitively, and is not exactly
// one of the closed list, so a misspelled override cannot silently fall back.
// The error names the variable, not its value.
func CheckEnviron(environ []string) error {
	for _, kv := range environ {
		name, _, _ := strings.Cut(kv, "=")
		if name == "" {
			continue
		}
		if strings.HasPrefix(strings.ToUpper(name), EnvPrefix) && !knownEnv[name] {
			return &Error{Code: CodeUnknownEnvironment, Field: name, Reason: "is not a recognized RICEVANTA_SERVER_ variable"}
		}
	}
	return nil
}

// LookupFrom returns a lookup function over an environ slice; the last
// assignment of a name wins, as in os.Getenv.
func LookupFrom(environ []string) func(string) (string, bool) {
	m := make(map[string]string, len(environ))
	for _, kv := range environ {
		if name, value, ok := strings.Cut(kv, "="); ok && name != "" {
			m[name] = value
		}
	}
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

func envString(env func(string) (string, bool), name string) (*string, error) {
	v, ok := env(name)
	if !ok {
		return nil, nil
	}
	if !utf8.ValidString(v) {
		return nil, invalid(name, "is not valid UTF-8")
	}
	return &v, nil
}

// applyEnv overlays the environment on the decoded file. Values then pass the
// same validation as file values.
func applyEnv(r *raw, env func(string) (string, bool)) error {
	if v, err := envString(env, EnvRoles); err != nil {
		return err
	} else if v != nil {
		roles := strings.Split(*v, ",")
		r.Roles = &roles
	}
	listener := func() *rawListener {
		if r.Listen == nil {
			r.Listen = &rawListen{}
		}
		if r.Listen.API == nil {
			r.Listen.API = &rawListener{}
		}
		return r.Listen.API
	}
	tls := func() *rawTLS {
		l := listener()
		if l.TLS == nil {
			l.TLS = &rawTLS{}
		}
		return l.TLS
	}
	for _, o := range []struct {
		name string
		set  func(*string)
	}{
		{EnvListenAPIAddress, func(v *string) { listener().Address = v }},
		{EnvListenAPITLSMode, func(v *string) { tls().Mode = v }},
		{EnvListenAPITLSCert, func(v *string) { tls().CertificateFile = v }},
		{EnvListenAPITLSKey, func(v *string) { tls().KeyFile = v }},
		{EnvLogLevel, func(v *string) {
			if r.Log == nil {
				r.Log = &rawLog{}
			}
			r.Log.Level = v
		}},
	} {
		v, err := envString(env, o.name)
		if err != nil {
			return err
		}
		if v != nil {
			o.set(v)
		}
	}
	if v, err := envString(env, EnvConsoleEnabled); err != nil {
		return err
	} else if v != nil {
		var b bool
		switch *v {
		case "true":
			b = true
		case "false":
		default:
			return invalid(EnvConsoleEnabled, "must be true or false")
		}
		if r.Console == nil {
			r.Console = &rawConsole{}
		}
		r.Console.Enabled = &b
	}
	return nil
}
