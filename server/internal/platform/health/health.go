// Package health holds the readiness registry and the /healthz and /readyz
// handlers of docs/specs/server-runtime.md section 5. Bodies disclose only
// states: never a version, hostname, build identity, address or setting.
package health

import (
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// State is one role's readiness state.
type State string

// Role states.
const (
	Starting State = "starting"
	Ready    State = "ready"
	Stopping State = "stopping"
)

// roleOrder is the BE-03 role order used in readiness bodies.
var roleOrder = []string{"api", "agent", "device", "radius", "jobs"}

// Registry tracks the readiness of each configured role.
type Registry struct {
	mu     sync.RWMutex
	roles  []string
	states map[string]State
}

// NewRegistry returns a registry with every role starting.
func NewRegistry(roles []string) *Registry {
	r := &Registry{states: map[string]State{}}
	for _, name := range roleOrder {
		for _, c := range roles {
			if c == name {
				r.roles = append(r.roles, name)
				r.states[name] = Starting
			}
		}
	}
	return r
}

// Set records the state of one configured role; other names are ignored.
func (r *Registry) Set(role string, s State) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if previous, ok := r.states[role]; ok && previous != Stopping {
		r.states[role] = s
	}
}

// SetAll records s for every configured role.
func (r *Registry) SetAll(s State) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for k := range r.states {
		if r.states[k] == Stopping {
			continue
		}
		r.states[k] = s
	}
}

// Readiness returns the /readyz status code and body: 200 and ready when
// every role is ready, otherwise 503 with stopping when any role is stopping
// and starting else.
func (r *Registry) Readiness() (int, []byte) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	status := Ready
	var b strings.Builder
	for i, name := range r.roles {
		s := r.states[name]
		switch {
		case s == Stopping:
			status = Stopping
		case s != Ready && status != Stopping:
			status = Starting
		}
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`"` + name + `":"` + string(s) + `"`)
	}
	if len(r.roles) == 0 {
		status = Starting
	}
	body := []byte(`{"status":"` + string(status) + `","roles":{` + b.String() + `}}`)
	if status == Ready {
		return http.StatusOK, body
	}
	return http.StatusServiceUnavailable, body
}

var liveness = []byte(`{"status":"ok"}`)

// Healthz answers liveness: 200 {"status":"ok"} while the process serves.
func (r *Registry) Healthz() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		respond(w, req, http.StatusOK, liveness)
	})
}

// Readyz answers readiness from the registry.
func (r *Registry) Readyz() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		status, body := r.Readiness()
		respond(w, req, status, body)
	})
}

func respond(w http.ResponseWriter, req *http.Request, status int, body []byte) {
	h := w.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		h.Set("Allow", "GET, HEAD")
		h.Set("Content-Type", "application/problem+json")
		h.Set("Cache-Control", "no-store")
		status = http.StatusMethodNotAllowed
		body = []byte(`{"status":405,"title":"Method Not Allowed","type":"about:blank"}`)
	} else {
		h.Set("Content-Type", "application/json")
		h.Set("Cache-Control", "no-store")
	}
	h.Set("Content-Length", strconv.Itoa(len(body)))
	// The write-progress bound of spec section 4; bodies are below 16 KiB.
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(10 * time.Second))
	w.WriteHeader(status)
	if req.Method != http.MethodHead {
		w.Write(body)
	}
}
