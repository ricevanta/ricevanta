package runtime

import (
	"log/slog"
	"net/http"
	"time"
)

// catalogue is the closed set of log event tokens of spec section 7.
var catalogue = map[string]bool{
	"starting": true, "config_loaded": true, "console_verified": true, "listening": true, "ready": true,
	"request": true, "stop_requested": true, "shutdown_complete": true, "shutdown_timeout": true, "startup_failed": true,
}

// parseLevel maps log.level to a slog level; configuration validation
// admits only the four names.
func parseLevel(level string) slog.Level {
	switch level {
	case "error":
		return slog.LevelError
	case "warn":
		return slog.LevelWarn
	case "debug":
		return slog.LevelDebug
	}
	return slog.LevelInfo
}

// recorder captures the status and body size for the request log. Unwrap
// keeps http.ResponseController working through it.
type recorder struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (r *recorder) WriteHeader(code int) {
	if r.status == 0 {
		r.status = code
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *recorder) Write(p []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	n, err := r.ResponseWriter.Write(p)
	r.bytes += int64(n)
	return n, err
}

func (r *recorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

// Bounds on logged request fields. net/http accepts a method token of any
// length that fits max_header_bytes.
const (
	maxLoggedPath   = 1024
	maxLoggedMethod = 32
)

// logRequests records method, escaped path without query, status, bytes,
// duration and the TCP peer. No header, cookie, body or query is logged; at
// debug level the response's cache decision is added.
func logRequests(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &recorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)
		path := r.URL.EscapedPath()
		if len(path) > maxLoggedPath {
			path = path[:maxLoggedPath]
		}
		method := r.Method
		if len(method) > maxLoggedMethod {
			method = method[:maxLoggedMethod]
		}
		status := rec.status
		if status == 0 {
			status = http.StatusOK
		}
		attrs := []any{
			"method", method, "path", path, "status", status, "bytes", rec.bytes,
			"duration_ms", time.Since(start).Milliseconds(), "remote", r.RemoteAddr,
		}
		if log.Enabled(r.Context(), slog.LevelDebug) {
			h := w.Header()
			attrs = append(attrs, "cache_control", h.Get("Cache-Control"), "content_encoding", h.Get("Content-Encoding"))
		}
		log.Info("request", attrs...)
	})
}
