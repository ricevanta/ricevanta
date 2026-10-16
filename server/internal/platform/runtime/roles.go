package runtime

// gates names what each blocked role waits for (spec section 8). Only api is
// admissible in this build.
var gates = map[string]string{
	"agent":  "waits for the authority journal, enrollment and mTLS contracts (analysis section 3.1 row 3, BE-12, PKI-02)",
	"device": "waits for the authority journal, enrollment and mTLS contracts (analysis section 3.1 row 3, BE-12, PKI-02)",
	"radius": "waits for the RAD-02 to RAD-06 contracts",
	"jobs":   "waits for the database and journal slices",
}

// RoleError reports a configured role this build refuses to start.
type RoleError struct {
	Role string
	Gate string
}

func (e *RoleError) Error() string { return "role_blocked: " + e.Role + " " + e.Gate }

// Admit returns a RoleError for the first configured role that is blocked.
func Admit(roles []string) error {
	for _, r := range roles {
		if r == "api" {
			continue
		}
		gate, ok := gates[r]
		if !ok {
			gate = "is not a role of this build"
		}
		return &RoleError{Role: r, Gate: gate}
	}
	return nil
}
