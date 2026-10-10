package catalogue

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

type nameCase struct{ ID, Name, ValidateError, LookupError string }

func nameFixtures(t testing.TB) (string, []nameCase) {
	t.Helper()
	b, err := os.ReadFile("../../../../schemas/permissions/v1/fixtures/names.json")
	if err != nil {
		t.Fatal(err)
	}
	var wire struct {
		CatalogueCase string `json:"catalogue_case"`
		Cases         []struct {
			ID, Name      string
			ValidateError string `json:"validate_error"`
			LookupError   string `json:"lookup_error"`
		}
	}
	if err := json.Unmarshal(b, &wire); err != nil {
		t.Fatal(err)
	}
	rows := make([]nameCase, len(wire.Cases))
	for i, r := range wire.Cases {
		rows[i] = nameCase{r.ID, r.Name, r.ValidateError, r.LookupError}
	}
	return wire.CatalogueCase, rows
}
func TestValidateName(t *testing.T) {
	_, rows := nameFixtures(t)
	for _, r := range rows {
		t.Run(r.ID, func(t *testing.T) {
			err := ValidateName(r.Name)
			if (err == nil) != (r.ValidateError == "") || err != nil && !errors.Is(err, ErrNameFormat) {
				t.Fatalf("got %v, want %s", err, r.ValidateError)
			}
		})
	}
	for _, s := range []string{"a.b.c", strings.Repeat("a", 32) + "." + strings.Repeat("b", 32) + "." + strings.Repeat("c", 32), strings.Repeat("a", 33) + ".b.c", strings.Repeat("a", 32) + "." + strings.Repeat("b", 32) + "." + strings.Repeat("c", 33), "a.b.c\x00", "a.b.\xff", "a.b.а", "a.b.c ", "a.b.c\n", "a.b.c-d", "a.b.c*", "a._b.c"} {
		if (ValidateName(s) == nil) != nameOracle(s) {
			t.Fatalf("boundary %q", s)
		}
	}
}

// The oracle splits tokens, independently of the production state machine.
func nameOracle(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return false
	}
	for _, p := range parts {
		if len(p) < 1 || len(p) > 32 || p[0] < 'a' || p[0] > 'z' {
			return false
		}
		for _, b := range []byte(p) {
			if !(b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '_') {
				return false
			}
		}
	}
	return true
}
func FuzzValidateName(f *testing.F) {
	_, rows := nameFixtures(f)
	for _, r := range rows {
		f.Add(r.Name)
	}
	for _, s := range []string{"a.b.\xff", "a.b.c\x00", strings.Repeat("a", 33) + ".b.c", strings.Repeat("a", 32) + "." + strings.Repeat("b", 32) + "." + strings.Repeat("c", 33)} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		err := ValidateName(s)
		if (err == nil) != nameOracle(s) || err != nil && !errors.Is(err, ErrNameFormat) {
			t.Fatalf("grammar disagreement: %v", err)
		}
	})
}
