package health_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/ricevanta/ricevanta/server/internal/platform/health"
)

// validBody repeats schemas/server/health/v1/readiness.schema.json: either
// exactly {"status":"ok"}, or a status of ready, starting or stopping with
// one to five known roles in known states, and nothing else.
func validBody(data []byte) error {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(data, &doc); err != nil {
		return err
	}
	var status string
	if err := json.Unmarshal(doc["status"], &status); err != nil {
		return errors.New("status is not a string")
	}
	if len(doc) == 1 && status == "ok" {
		return nil
	}
	if len(doc) != 2 || (status != "ready" && status != "starting" && status != "stopping") {
		return errors.New("not a readiness body")
	}
	var roles map[string]string
	if err := json.Unmarshal(doc["roles"], &roles); err != nil || len(roles) < 1 || len(roles) > 5 {
		return errors.New("roles must map one to five roles to states")
	}
	known := map[string]bool{"api": true, "agent": true, "device": true, "radius": true, "jobs": true}
	for r, st := range roles {
		if !known[r] || (st != "ready" && st != "starting" && st != "stopping") {
			return errors.New("unknown role or state")
		}
	}
	return nil
}

func ValidBody(t *testing.T, data []byte) {
	t.Helper()
	if err := validBody(data); err != nil {
		t.Fatalf("body %q violates the readiness schema: %v", data, err)
	}
}

// TestSchemaCasesAgreeWithValidBody keeps the mirror above honest.
func TestSchemaCasesAgreeWithValidBody(t *testing.T) {
	data, err := os.ReadFile("../../../../schemas/server/health/v1/schema-cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases struct {
		Cases []struct {
			ID       string          `json:"id"`
			Valid    bool            `json:"valid"`
			Instance json.RawMessage `json:"instance"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	for _, c := range cases.Cases {
		if ok := validBody(c.Instance) == nil; ok != c.Valid {
			t.Errorf("%s: mirror says %v, schema case says %v", c.ID, ok, c.Valid)
		}
	}
}

func get(t *testing.T, h http.Handler, method string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(method, "/", nil))
	return w
}

func checkHeaders(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	for k, v := range map[string]string{
		"Content-Type":           "application/json",
		"Cache-Control":          "no-store",
		"X-Content-Type-Options": "nosniff",
	} {
		if got := w.Header().Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	for _, k := range []string{"Server", "X-Version"} {
		if w.Header().Get(k) != "" {
			t.Errorf("%s disclosed", k)
		}
	}
}

func TestLiveness(t *testing.T) {
	r := health.NewRegistry([]string{"api"})
	for _, m := range []string{"GET", "HEAD"} {
		w := get(t, r.Healthz(), m)
		if w.Code != 200 {
			t.Fatalf("%s: %d", m, w.Code)
		}
		checkHeaders(t, w)
		if m == "GET" {
			if w.Body.String() != `{"status":"ok"}` {
				t.Fatalf("body %q", w.Body.String())
			}
			ValidBody(t, w.Body.Bytes())
		} else if w.Body.Len() != 0 {
			t.Fatal("HEAD body")
		}
		if w.Header().Get("Content-Length") != "15" {
			t.Fatalf("Content-Length %q", w.Header().Get("Content-Length"))
		}
	}
}

func TestReadinessTransitions(t *testing.T) {
	r := health.NewRegistry([]string{"api"})
	steps := []struct {
		apply  func()
		status int
		body   string
	}{
		{func() {}, 503, `{"status":"starting","roles":{"api":"starting"}}`},
		{func() { r.Set("api", health.Ready) }, 200, `{"status":"ready","roles":{"api":"ready"}}`},
		{func() { r.SetAll(health.Stopping) }, 503, `{"status":"stopping","roles":{"api":"stopping"}}`},
	}
	for _, s := range steps {
		s.apply()
		w := get(t, r.Readyz(), "GET")
		if w.Code != s.status || w.Body.String() != s.body {
			t.Fatalf("got %d %s, want %d %s", w.Code, w.Body.String(), s.status, s.body)
		}
		checkHeaders(t, w)
		ValidBody(t, w.Body.Bytes())
	}
}

func TestReadinessManyRoles(t *testing.T) {
	r := health.NewRegistry([]string{"jobs", "api"})
	r.Set("api", health.Ready)
	w := get(t, r.Readyz(), "GET")
	if w.Code != 503 || w.Body.String() != `{"status":"starting","roles":{"api":"ready","jobs":"starting"}}` {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	r.Set("jobs", health.Ready)
	if w := get(t, r.Readyz(), "GET"); w.Code != 200 {
		t.Fatalf("all ready: %d", w.Code)
	}
	r.Set("jobs", health.Stopping)
	if w := get(t, r.Readyz(), "GET"); w.Code != 503 || w.Body.String() != `{"status":"stopping","roles":{"api":"ready","jobs":"stopping"}}` {
		t.Fatalf("one stopping: %d %s", w.Code, w.Body.String())
	}
}

func TestMethodNotAllowed(t *testing.T) {
	r := health.NewRegistry([]string{"api"})
	for _, h := range []http.Handler{r.Healthz(), r.Readyz()} {
		for _, m := range []string{"POST", "PUT", "DELETE", "OPTIONS"} {
			w := get(t, h, m)
			if w.Code != 405 || w.Header().Get("Allow") != "GET, HEAD" || w.Header().Get("Content-Type") != "application/problem+json" {
				t.Fatalf("%s: %d %v", m, w.Code, w.Header())
			}
		}
	}
}

func TestStoppingRejectsLateReady(t *testing.T) {
	r := health.NewRegistry([]string{"api"})
	r.SetAll(health.Stopping)
	r.Set("api", health.Ready)
	r.SetAll(health.Ready)
	if code, body := r.Readiness(); code != 503 || string(body) != `{"status":"stopping","roles":{"api":"stopping"}}` {
		t.Fatalf("late readiness: %d %s", code, body)
	}
}
