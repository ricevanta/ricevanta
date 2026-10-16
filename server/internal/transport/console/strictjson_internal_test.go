package console

import (
	"encoding/json"
	"testing"
)

// TestEscapedSurrogatePairAccepted requires valid escaped pairs in values and
// keys to pass strict checks and decode to their Unicode code points.
func TestEscapedSurrogatePairAccepted(t *testing.T) {
	for _, tc := range []struct {
		name, doc, key, value string
	}{
		{"escaped value", `{"name":"\ud83d\ude00"}`, "name", "\U0001F600"},
		{"escaped values within text", `{"name":"a\ud83d\ude00b\ud83d\ude00"}`, "name", "a\U0001F600b\U0001F600"},
		{"escaped key", `{"\ud83d\ude00":"value"}`, "\U0001F600", "value"},
		{"literal UTF-8 value", `{"name":"😀"}`, "name", "\U0001F600"},
		{"literal UTF-8 values within text", `{"name":"a😀b😀"}`, "name", "a\U0001F600b\U0001F600"},
		{"literal UTF-8 key", `{"😀":"value"}`, "\U0001F600", "value"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := []byte(tc.doc)
			if err := checkStrictJSON(data); err != nil {
				t.Fatalf("%s: %v", tc.doc, err)
			}
			var decoded map[string]string
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatal(err)
			}
			if got, ok := decoded[tc.key]; len(decoded) != 1 || !ok || got != tc.value {
				t.Fatalf("decoded %q, want key %q and value %q", decoded, tc.key, tc.value)
			}
		})
	}
	for _, doc := range []string{`"\ud83d"`, `"\ude00"`, `"\ud83dA"`, `"\ud83d\\ude00"`, `"\ude00\ud83d"`} {
		if err := checkStrictJSON([]byte(doc)); err == nil {
			t.Fatalf("%s accepted", doc)
		}
	}
}
