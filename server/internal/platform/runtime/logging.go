package runtime

import (
	"io"
	"log/slog"
	"net/http"
	"time"
)

// catalogue is the closed set of log event tokens of spec section 7.
var catalogue = map[string]bool{
	"starting": true, "config_loaded": true, "console_verified": true, "listening": true, "ready": true,
	"request": true, "stop_requested": true, "shutdown_complete": true, "shutdown_timeout": true, "startup_failed": true,
}

func newLogger(w io.Writer, level string) *slog.Logger {
	var l slog.Level
	switch level {
	case "error":
		l = slog.LevelError
	case "warn":
		l = slog.LevelWarn
	case "debug":
		l = slog.LevelDebug
	default:
		l = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: l}))
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

const maxLoggedPath = 1024

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
		status := rec.status
		if status == 0 {
			status = http.StatusOK
		}
		attrs := []any{
			"method", r.Method, "path", path, "status", status, "bytes", rec.bytes,
			"duration_ms", time.Since(start).Milliseconds(), "remote", r.RemoteAddr,
		}
		if log.Enabled(r.Context(), slog.LevelDebug) {
			h := w.Header()
			attrs = append(attrs, "cache_control", h.Get("Cache-Control"), "content_encoding", h.Get("Content-Encoding"))
		}
		log.Info("request", attrs...)
	})
}
