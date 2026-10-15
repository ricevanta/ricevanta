package console

import (
	"encoding/json"
	"testing"
)

// TestEscapedSurrogatePairAccepted: an escaped valid pair such as
// "😀" (U+1F600) is valid Unicode and must pass the strict
// checks and decode to the code point.
func TestEscapedSurrogatePairAccepted(t *testing.T) {
	for _, doc := range []string{
		`{"name":"😀"}`,
		`{"name":"a😀b😀"}`,
		`{"😀":1}`,
	} {
		if err := checkStrictJSON([]byte(doc)); err != nil {
			t.Fatalf("%s: %v", doc, err)
		}
	}
	var v map[string]string
	if err := json.Unmarshal([]byte(`{"name":"😀"}`), &v); err != nil || v["name"] != "\U0001F600" {
		t.Fatalf("decoded %q %v", v["name"], err)
	}
	for _, doc := range []string{`"\ud83d"`, `"\ude00"`, `"\ud83dA"`, `"\ud83d\\ude00"`, `"\ude00\ud83d"`} {
		if err := checkStrictJSON([]byte(doc)); err == nil {
			t.Fatalf("%s accepted", doc)
		}
	}
}
