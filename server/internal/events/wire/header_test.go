package wire

import (
	"strings"
	"testing"

	"github.com/ricevanta/ricevanta/server/internal/events/batch"
)

const validHeader = "v=1;class=raw;epoch=1;segment=0;first=0;last=0;count=1"

func TestParseHeaderFixtures(t *testing.T) {
	for _, c := range loadFixtures(t, "header") {
		t.Run(c.Name, func(t *testing.T) {
			d, err := ParseHeader(c.Values)
			requireResult(t, d, err, fixtureError(t, c.Error), fixtureDescriptor(t, c.Descriptor))
		})
	}
}

func TestParseHeaderErrorPrecedence(t *testing.T) {
	cases := []struct {
		values []string
		want   error
	}{
		{[]string{strings.Repeat("x", 140), validHeader}, ErrHeaderCount},
		{[]string{strings.Replace(validHeader, "v=1", "v=2", 1) + strings.Repeat("x", 140)}, ErrHeaderSize},
		{[]string{strings.Replace(strings.Replace(validHeader, "v=1", "v=2", 1), "epoch=1", "epoch=18446744073709551616", 1)}, ErrHeaderSyntax},
		{[]string{strings.Replace(strings.Replace(validHeader, "class=raw", "class=other", 1), "epoch=1", "epoch=0", 1)}, batch.ErrClass},
	}
	for _, c := range cases {
		d, err := ParseHeader(c.values)
		requireResult(t, d, err, c.want, batch.Descriptor{})
	}
}

func TestParseHeaderNumericBounds(t *testing.T) {
	for _, key := range []string{"v", "epoch", "segment", "first", "last", "count"} {
		original := strings.Split(validHeader, ";")
		for _, token := range []string{"+1", "-1", "0x1", "1e0", "01", "", "1.0"} {
			parts := append([]string(nil), original...)
			for i, p := range parts {
				if strings.HasPrefix(p, key+"=") {
					parts[i] = key + "=" + token
				}
			}
			d, err := ParseHeader([]string{strings.Join(parts, ";")})
			requireResult(t, d, err, ErrHeaderSyntax, batch.Descriptor{})
		}
	}
	for _, replacement := range []struct{ old, new string }{
		{"v=1", "v=256"}, {"count=1", "count=4294967296"},
		{"epoch=1", "epoch=18446744073709551616"}, {"segment=0", "segment=18446744073709551616"},
		{"first=0", "first=18446744073709551616"}, {"last=0", "last=18446744073709551616"},
	} {
		d, err := ParseHeader([]string{strings.Replace(validHeader, replacement.old, replacement.new, 1)})
		requireResult(t, d, err, ErrHeaderSyntax, batch.Descriptor{})
	}
	for _, c := range []struct {
		value string
		want  error
	}{
		{strings.Replace(validHeader, "v=1", "v=255", 1), ErrVersion},
		{strings.Replace(validHeader, "count=1", "count=4294967295", 1), batch.ErrRecordCount},
	} {
		d, err := ParseHeader([]string{c.value})
		requireResult(t, d, err, c.want, batch.Descriptor{})
	}
}

func TestParseHeaderZeroOnError(t *testing.T) {
	for _, c := range loadFixtures(t, "header") {
		if c.Error != nil {
			d, err := ParseHeader(c.Values)
			requireResult(t, d, err, fixtureError(t, c.Error), batch.Descriptor{})
		}
	}
	for _, token := range []string{"RAW", "Raw", "r\x00aw", "r\raw", "r\naw", "r\xffaw", "r\xc0\xafaw", "r aw", "r,aw"} {
		d, err := ParseHeader([]string{strings.Replace(validHeader, "class=raw", "class="+token, 1)})
		requireResult(t, d, err, ErrHeaderSyntax, batch.Descriptor{})
	}
	parts := strings.Split(validHeader, ";")
	for i := range parts {
		for j := i + 1; j < len(parts); j++ {
			reordered := append([]string(nil), parts...)
			reordered[i], reordered[j] = reordered[j], reordered[i]
			d, err := ParseHeader([]string{strings.Join(reordered, ";")})
			requireResult(t, d, err, ErrHeaderSyntax, batch.Descriptor{})
		}
	}
	maxHeader := "v=1;class=findings;epoch=18446744073709551615;segment=18446744073709551615;first=18446744073709541616;last=18446744073709551615;count=10000"
	if len(maxHeader) != 139 {
		t.Fatal("wrong boundary test length")
	}
	d, err := ParseHeader([]string{maxHeader})
	if err != nil || d.Validate() != nil {
		t.Fatalf("139-byte header: %v", err)
	}
	d, err = ParseHeader([]string{maxHeader + "x"})
	requireResult(t, d, err, ErrHeaderSize, batch.Descriptor{})
}

func FuzzParseHeader(f *testing.F) {
	for _, c := range loadFixtures(f, "header") {
		value := ""
		if len(c.Values) > 0 {
			value = c.Values[0]
		}
		f.Add(value, uint8(len(c.Values)))
	}
	f.Fuzz(func(t *testing.T, value string, selector uint8) {
		var values []string
		switch selector % 3 {
		case 1:
			values = []string{value}
		case 2:
			values = []string{value, value}
		}
		d, err := ParseHeader(values)
		if err != nil {
			if d != (batch.Descriptor{}) {
				t.Fatal("nonzero error result")
			}
			return
		}
		if len(values) != 1 || d.Validate() != nil || canonicalHeader(d) != value || batch.ValidateBatchID(d.BatchID(), d) != nil {
			t.Fatal("invalid successful parse")
		}
	})
}
