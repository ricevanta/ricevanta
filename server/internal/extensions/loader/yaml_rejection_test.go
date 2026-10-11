package loader

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/ricevanta/ricevanta/server/internal/extensions/loader/internal/yamltokens"
)

// Negative controls must fail inside the same assertion used by tests and fuzzing.
func TestAgreementRejectsOutcomeMismatch(t *testing.T) {
	for _, name := range []string{"oracle-rejects", "candidate-rejects", "check-class", "decode-class"} {
		t.Run(name, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestAgreementOutcomeChild$", "-test.v")
			cmd.Env = append(os.Environ(), "RICEVANTA_AGREEMENT_CONTROL="+name)
			out, err := cmd.CombinedOutput()
			if err == nil || !strings.Contains(string(out), "acceptance/error disagreement") {
				t.Fatalf("assertion must reject %s: err=%v\n%s", name, err, out)
			}
		})
	}
}

func TestAgreementOutcomeChild(t *testing.T) {
	name := os.Getenv("RICEVANTA_AGREEMENT_CONTROL")
	if name == "" {
		t.Skip("agreement negative-control child only")
	}
	input := []byte("a: b\n")
	if name != "candidate-rejects" {
		input = []byte("[!x a]\n")
	}
	want, wantErr := referenceAcceptance(input)
	got, budget, decodeErr := yamltokens.Decode(input)
	checkErr := yamltokens.Check(input)
	switch name {
	case "oracle-rejects":
		if wantErr != yamltokens.ErrTag {
			t.Fatal("oracle must reject tag")
		}
		// A broken candidate can report success without returning a tree.
		checkErr, decodeErr = nil, nil
	case "candidate-rejects":
		if wantErr != nil || checkErr != nil || decodeErr != nil {
			t.Fatal("valid fixture must be accepted")
		}
		checkErr, decodeErr = yamltokens.ErrSyntax, yamltokens.ErrSyntax
	case "check-class":
		if wantErr != yamltokens.ErrTag || checkErr != wantErr || decodeErr != wantErr {
			t.Fatal("tag fixture class")
		}
		checkErr = yamltokens.ErrSyntax
	case "decode-class":
		if wantErr != yamltokens.ErrTag || checkErr != wantErr || decodeErr != wantErr {
			t.Fatal("tag fixture class")
		}
		decodeErr = yamltokens.ErrSyntax
	default:
		t.Fatal("unknown negative control")
	}
	assertAgreementResults(t, want, wantErr, checkErr, got, budget, decodeErr)
}
