package eventid

import (
	"errors"
	"testing"
)

const exampleUUIDv7 = "017f22e2-79b0-7cc3-98c4-dc0c0c07398f"

func TestParse(t *testing.T) {
	want := ID{
		0x01, 0x7f, 0x22, 0xe2,
		0x79, 0xb0,
		0x7c, 0xc3,
		0x98, 0xc4,
		0xdc, 0x0c, 0x0c, 0x07, 0x39, 0x8f,
	}

	got, err := Parse(exampleUUIDv7)
	if err != nil {
		t.Fatalf("Parse(%q) error = %v, want nil", exampleUUIDv7, err)
	}
	if got != want {
		t.Fatalf("Parse(%q) = %x, want %x", exampleUUIDv7, got, want)
	}
	if got.String() != exampleUUIDv7 {
		t.Fatalf("Parse(%q).String() = %q, want exact round trip", exampleUUIDv7, got.String())
	}
}

func TestParseRejectsMalformedText(t *testing.T) {
	tests := []struct {
		name        string
		text        string
		exactLength bool
	}{
		{name: "missing dashes", text: "017f22e279b07cc398c4dc0c0c07398f"},
		{name: "too short", text: "017f22e2-79b0-7cc3-98c4-dc0c0c07398"},
		{name: "too long", text: "017f22e2-79b0-7cc3-98c4-dc0c0c07398f0"},
		{name: "wrong first dash", text: "017f22e2_79b0-7cc3-98c4-dc0c0c07398f", exactLength: true},
		{name: "wrong second dash", text: "017f22e2-79b0_7cc3-98c4-dc0c0c07398f", exactLength: true},
		{name: "wrong third dash", text: "017f22e2-79b0-7cc3_98c4-dc0c0c07398f", exactLength: true},
		{name: "wrong fourth dash", text: "017f22e2-79b0-7cc3-98c4_dc0c0c07398f", exactLength: true},
		{name: "extra dash in hex", text: "00000000-0000-0000-0000-00000000-000", exactLength: true},
		{name: "invalid hex", text: "017f22e2-79b0-7cc3-98c4-dc0c0c07398g"},
		{name: "non ASCII", text: "017f22e2-79b0-7cc3-98c4-dc0c0c0739é"},
		{name: "invalid UTF-8", text: "017f22e2-79b0-7cc3-98c4-dc0c0c07398\xff"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.exactLength && len(tt.text) != 36 {
				t.Fatalf("fixture length = %d, want 36", len(tt.text))
			}
			assertParseError(t, tt.text, ErrFormat)
		})
	}
}

func TestParseRejectsNonCanonicalText(t *testing.T) {
	tests := []string{
		"017F22E2-79B0-7CC3-98C4-DC0C0C07398F",
		"017f22e2-79b0-7cc3-98c4-dc0c0c07398F",
	}
	for _, text := range tests {
		assertParseError(t, text, ErrNonCanonical)
	}
}

func TestParseRejectsWrongVersion(t *testing.T) {
	assertParseError(t, "017f22e2-79b0-6cc3-98c4-dc0c0c07398f", ErrVersion)
}

func TestParseRejectsWrongVariant(t *testing.T) {
	assertParseError(t, "017f22e2-79b0-7cc3-78c4-dc0c0c07398f", ErrVariant)
}

func TestParseErrorPrecedence(t *testing.T) {
	tests := []struct {
		name string
		text string
		want error
	}{
		{
			name: "bad dash before uppercase",
			text: "017F22e2_79b0-7cc3-98c4-dc0c0c07398f",
			want: ErrFormat,
		},
		{
			name: "uppercase before invalid hexadecimal",
			text: "017F22e2-79b0-7cc3-98c4-dc0c0c07398g",
			want: ErrNonCanonical,
		},
		{
			name: "invalid hexadecimal before wrong version",
			text: "017f22e2-79b0-6cc3-98c4-dc0c0c07398g",
			want: ErrFormat,
		},
		{
			name: "wrong version before wrong variant",
			text: "017f22e2-79b0-6cc3-78c4-dc0c0c07398f",
			want: ErrVersion,
		},
		{
			name: "uppercase before invalid UTF-8",
			text: "017F22e2-79b0-7cc3-98c4-dc0c0c07398\xff",
			want: ErrNonCanonical,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if len(tt.text) != 36 {
				t.Fatalf("fixture length = %d, want 36", len(tt.text))
			}
			assertParseError(t, tt.text, tt.want)
		})
	}
}

func TestStringArbitraryID(t *testing.T) {
	tests := []struct {
		name string
		id   ID
		want string
	}{
		{
			name: "zero",
			want: "00000000-0000-0000-0000-000000000000",
		},
		{
			name: "wrong version",
			id:   ID{6: 0x60, 8: 0x80},
			want: "00000000-0000-6000-8000-000000000000",
		},
		{
			name: "wrong variant",
			id:   ID{6: 0x70, 8: 0x70},
			want: "00000000-0000-7000-7000-000000000000",
		},
		{
			name: "all bytes",
			id: ID{
				0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
				0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
			},
			want: "00112233-4455-6677-8899-aabbccddeeff",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.id.String(); got != tt.want {
				t.Fatalf("ID.String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func FuzzParse(f *testing.F) {
	seeds := []string{
		exampleUUIDv7,
		"017F22E2-79B0-7CC3-98C4-DC0C0C07398F",
		"017f22e279b07cc398c4dc0c0c07398f",
		"017f22e2-79b0-6cc3-98c4-dc0c0c07398f",
		"017f22e2-79b0-7cc3-78c4-dc0c0c07398f",
		"017F22e_2-79b0-7cc3-98c4-dc0c0c07398f",
		"017F22e2-79b0-7cc3-98c4-dc0c0c07398g",
		"017f22e2-79b0-7cc3-98c4-dc0c0c0739é",
		"017f22e2-79b0-7cc3-98c4-dc0c0c07398\xff",
		"017f22e2-79b0-6cc3-98c4-dc0c0c07398g",
		"017f22e2-79b0-6cc3-78c4-dc0c0c07398f",
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, text string) {
		id, err := Parse(text)
		if err != nil {
			if id != (ID{}) {
				t.Fatalf("Parse(%q) returned nonzero ID %x with error %v", text, id, err)
			}
			return
		}

		canonical := id.String()
		if canonical != text {
			t.Fatalf("successful Parse(%q).String() = %q", text, canonical)
		}
		roundTrip, roundTripErr := Parse(canonical)
		if roundTripErr != nil {
			t.Fatalf("Parse(Parse(%q).String()) error = %v", text, roundTripErr)
		}
		if roundTrip != id {
			t.Fatalf("Parse(Parse(%q).String()) = %x, want %x", text, roundTrip, id)
		}
	})
}

func assertParseError(t *testing.T, text string, want error) {
	t.Helper()

	id, err := Parse(text)
	if !errors.Is(err, want) {
		t.Fatalf("Parse(%q) error = %v, want errors.Is(_, %v)", text, err, want)
	}
	if id != (ID{}) {
		t.Fatalf("Parse(%q) ID = %x, want zero", text, id)
	}
}
