//go:build rustinterop

package body

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ricevanta/ricevanta/server/internal/events/batch"
	"github.com/ricevanta/ricevanta/server/internal/events/eventid"
	"github.com/ricevanta/ricevanta/server/internal/events/wire"
)

const writerBytes = 4_194_304

// Each pipe has a hard cap, including stderr from a malformed child.
type writerCapture struct {
	buffer bytes.Buffer
	limit  int
}

func (b *writerCapture) Write(p []byte) (int, error) {
	if len(p) > b.limit-b.buffer.Len() {
		return 0, fmt.Errorf("child output bound")
	}
	return b.buffer.Write(p)
}
func writerRun(path string, input []byte) (string, []byte, error) {
	if !filepath.IsAbs(path) {
		return "", nil, fmt.Errorf("RICEVANTA_BATCH_VECTOR must be an absolute executable path")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path)
	cmd.Stdin = bytes.NewReader(input)
	out := &writerCapture{limit: 5_000_141}
	stderr := &writerCapture{limit: 256}
	cmd.Stdout = out
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		return "", nil, fmt.Errorf("writer child failed: %w", err)
	}
	return writerResponse(out.buffer.Bytes())
}
func writerResponse(output []byte) (string, []byte, error) {
	i := bytes.IndexByte(output, '\n')
	if i < 1 || i > 140 || len(output)-i-1 < 48 || len(output) > 5_000_141 {
		return "", nil, fmt.Errorf("malformed writer response")
	}
	h := string(output[:i])
	if _, err := wire.ParseHeader([]string{h}); err != nil {
		return "", nil, err
	}
	return h, bytes.Clone(output[i+1:]), nil
}
func writerPath(t testing.TB) string {
	t.Helper()
	p := os.Getenv("RICEVANTA_BATCH_VECTOR")
	if !filepath.IsAbs(p) {
		t.Fatal("RICEVANTA_BATCH_VECTOR must be an absolute executable path")
	}
	return p
}
func writerSegment(d batch.Descriptor, payloads [][]byte) []byte {
	b := make([]byte, 32)
	copy(b, "RVSP")
	binary.LittleEndian.PutUint16(b[4:], 1)
	b[6] = byte(d.Class)
	binary.LittleEndian.PutUint64(b[8:], d.StreamEpoch)
	binary.LittleEndian.PutUint64(b[16:], d.SegmentID)
	binary.LittleEndian.PutUint64(b[24:], d.FirstSequence)
	table := crc32.MakeTable(crc32.Castagnoli)
	for i, p := range payloads {
		record := make([]byte, 16+len(p))
		binary.LittleEndian.PutUint32(record, uint32(len(p)))
		binary.LittleEndian.PutUint64(record[8:], d.FirstSequence+uint64(i))
		copy(record[16:], p)
		binary.LittleEndian.PutUint32(record[4:], crc32.Checksum(record[8:], table))
		b = append(b, record...)
	}
	return b
}
func writerDecode(h string, b []byte, device string) (batch.Descriptor, []Line, error) {
	r := &io.LimitedReader{R: bytes.NewReader(b), N: wire.MaxCompressedBytes + 1}
	d, err := wire.Decode([]string{h}, r)
	if err != nil {
		return d, nil, err
	}
	lines, err := Decode(r, d, device)
	return d, lines, err
}
func writerSuccess(t testing.TB, d batch.Descriptor, ps [][]byte, device string) (string, []byte, []Line) {
	t.Helper()
	input := writerSegment(d, ps)
	original := bytes.Clone(input)
	h, b, err := writerRun(writerPath(t), input)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(input, original) {
		t.Fatal("input mutated")
	}
	got, lines, err := writerDecode(h, b, device)
	if err != nil {
		t.Fatal(err)
	}
	if got != d || len(lines) != len(ps) {
		t.Fatal("descriptor/count mismatch")
	}
	for i, line := range lines {
		if line.Number != uint32(i+1) || !bytes.Equal(line.Raw, ps[i]) {
			t.Fatal("raw bytes or line position mismatch")
		}
		assertReferenceLine(t, line, ps[i], uint32(i+1), d, device)
	}
	return h, b, lines
}
func writerSentinel(t testing.TB, p *string) error {
	t.Helper()
	if p == nil {
		return nil
	}
	m := map[string]error{"body.ErrJSON": ErrJSON, "body.ErrJSONKeys": ErrJSONKeys, "body.ErrFields": ErrFields, "body.ErrEventID": ErrEventID, "body.ErrSequenceRange": ErrSequenceRange, "body.ErrSequencePosition": ErrSequencePosition, "body.ErrDeviceBinding": ErrDeviceBinding, "eventid.ErrFormat": eventid.ErrFormat, "eventid.ErrNonCanonical": eventid.ErrNonCanonical, "eventid.ErrVersion": eventid.ErrVersion, "eventid.ErrVariant": eventid.ErrVariant}
	e, ok := m[*p]
	if !ok {
		t.Fatalf("unknown fixture sentinel %s", *p)
	}
	return e
}
func TestRustWriterFixtures(t *testing.T) {
	writerPath(t)
	f := loadFixtures(t)
	selected := 0
	for _, c := range f.Cases {
		if c.Expected.Error != nil || c.PlainBytes > writerBytes || mustCount(c.Descriptor.Count) > 5000 {
			continue
		}
		selected++
		t.Run("body/"+c.Name, func(t *testing.T) {
			p, err := c.plain(f.Template)
			if err != nil {
				t.Fatal(err)
			}
			if !digestOK(p, c.PlainBytes, c.PlainSHA) || len(p) == 0 || p[len(p)-1] != '\n' {
				t.Fatal("plaintext oracle failed")
			}
			ps := bytes.Split(p[:len(p)-1], []byte{'\n'})
			d, err := c.descriptor()
			if err != nil {
				t.Fatal(err)
			}
			_, _, lines := writerSuccess(t, d, ps, c.Device)
			pos := 0
			for _, out := range c.Expected.Lines {
				want := writerSentinel(t, out.Error)
				cause := writerSentinel(t, out.Cause)
				for j := 0; j < out.Count; j++ {
					line := lines[pos]
					pos++
					if (line.Err == nil) != (want == nil) || want != nil && !errors.Is(line.Err, want) || cause != nil && !errors.Is(line.Err, cause) || line.DeviceMismatch != out.Mismatch {
						t.Fatal("fixture line error mismatch")
					}
					if want == nil {
						n, err := strconv.ParseUint(out.First, 10, 64)
						if err != nil {
							t.Fatal(err)
						}
						if line.Sequence != n+uint64(j) || line.EventID.String() != out.UID || line.DeviceUID != out.Device {
							t.Fatal("fixture identity mismatch")
						}
					}
				}
			}
			if pos != len(lines) {
				t.Fatal("uncompared fixture lines")
			}
		})
	}
	if selected == 0 {
		t.Fatal("no body fixture selected")
	}
	for _, kind := range []string{"header", "descriptor"} {
		data, err := os.ReadFile("../../../../schemas/events/v1/fixtures/" + kind + ".json")
		if err != nil {
			t.Fatal(err)
		}
		var f struct {
			Kind  string
			Cases []struct {
				Name         string
				Values       []string                                                    `json:"header_values"`
				Error        *string                                                     `json:"expected_error"`
				Descriptor   *struct{ Class, Epoch, Segment, First, Last, Count string } `json:"expected_descriptor"`
				Frame        string                                                      `json:"frame_hex"`
				Construction json.RawMessage
				Consumed     int `json:"consumed_bytes"`
			}
		}
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&f); err != nil {
			t.Fatal(err)
		}
		var tail any
		if dec.Decode(&tail) != io.EOF || f.Kind != kind {
			t.Fatal("invalid fixture container")
		}
		count := 0
		names := map[string]bool{}
		for _, c := range f.Cases {
			if c.Name == "" || names[c.Name] {
				t.Fatal("duplicate/empty fixture name")
			}
			names[c.Name] = true
			if c.Error != nil {
				continue
			}
			if c.Descriptor == nil || len(c.Values) != 1 {
				t.Fatal("invalid fixture success")
			}
			v := c.Descriptor
			fixture := bodyFixture{}
			fixture.Descriptor.Class = v.Class
			fixture.Descriptor.Epoch = v.Epoch
			fixture.Descriptor.Segment = v.Segment
			fixture.Descriptor.First = v.First
			fixture.Descriptor.Last = v.Last
			fixture.Descriptor.Count = v.Count
			d, err := fixture.descriptor()
			if err != nil {
				t.Fatal(err)
			}
			if d.RecordCount > 5000 {
				continue
			}
			count++
			t.Run(kind+"/"+c.Name, func(t *testing.T) {
				ps := writerRecords(fixtureTemplate(t), d.FirstSequence, int(d.RecordCount), 0)
				h, b, _ := writerSuccess(t, d, ps, "device-a")
				if h != c.Values[0] {
					t.Fatal("canonical header differs from fixture")
				}
				if kind == "descriptor" {
					want, err := hex.DecodeString(c.Frame)
					if err != nil || len(want) != 48 || c.Consumed != 48 || !bytes.Equal(b[:48], want) {
						t.Fatal("descriptor differs from fixture")
					}
				}
			})
		}
		if count == 0 {
			t.Fatal("no descriptor/header fixtures selected")
		}
	}
}
func fixtureTemplate(t testing.TB) string { t.Helper(); return loadFixtures(t).Template }
func writerRecords(template string, first uint64, count, total int) [][]byte {
	ps := make([][]byte, count)
	used := 0
	for i := range ps {
		p := []byte(strings.ReplaceAll(template, "SEQUENCE", strconv.FormatUint(first+uint64(i), 10)))
		if total > 0 {
			n := (total-used)/(count-i) - 1
			if n < len(p) {
				panic("invalid test recipe")
			}
			p = append(p, bytes.Repeat([]byte{' '}, n-len(p))...)
		}
		ps[i] = p
		used += len(p) + 1
	}
	return ps
}
func writerDescriptor(first uint64, count int) batch.Descriptor {
	return batch.Descriptor{Class: batch.ClassRaw, StreamEpoch: 1, FirstSequence: first, LastSequence: first + uint64(count-1), RecordCount: uint32(count)}
}
func TestRustWriterBoundaries(t *testing.T) {
	path := writerPath(t)
	template := fixtureTemplate(t)
	for _, tc := range []struct {
		first        uint64
		count, total int
	}{{0, 1, 0}, {^uint64(0), 1, 0}, {^uint64(0) - 1, 2, 0}, {0, 4999, 0}, {0, 5000, 0}, {0, 1, 255}, {0, 1, 256}, {0, 1, 65791}, {0, 1, 65792}, {0, 5, writerBytes - 1}, {0, 5, writerBytes}, {0, 1, 1_048_576}, {0, 1, 1_048_577}} {
		d := writerDescriptor(tc.first, tc.count)
		writerSuccess(t, d, writerRecords(template, tc.first, tc.count, tc.total), "device-a")
	}
	for _, p := range [][]byte{[]byte("x"), {0xff}, []byte("x \\n\\r\t"), []byte("é")} {
		writerSuccess(t, writerDescriptor(0, 1), [][]byte{p}, "device-a")
	}
	state := uint64(0x5249564241544348)
	next := func() uint64 { state ^= state << 13; state ^= state >> 7; state ^= state << 17; return state }
	for i := 0; i < 128; i++ {
		n := int(next()%12) + 1
		ps := writerRecords(template, 0, n, 0)
		for j := range ps {
			ps[j] = append(ps[j], bytes.Repeat([]byte{' '}, int(next()%200))...)
		}
		writerSuccess(t, writerDescriptor(0, n), ps, "device-a")
	}
	ps := make([][]byte, 4)
	for i := range ps {
		ps[i] = make([]byte, 1_048_575)
		for j := range ps[i] {
			b := byte(next())
			if b == 10 || b == 13 {
				b = 0
			}
			ps[i][j] = b
		}
		ps[i][0] = 'x'
	}
	writerSuccess(t, writerDescriptor(0, 4), ps, "device-a")
	// Failure vectors must publish no bytes and only a variant name.
	bad := []struct {
		input []byte
		name  string
	}{
		{writerSegment(writerDescriptor(0, 1), nil), "Empty"},
		{writerSegment(writerDescriptor(0, 5001), writerRecords(template, 0, 5001, 0)), "RecordCount"},
		{writerSegment(writerDescriptor(0, 5), writerRecords(template, 0, 5, writerBytes+1)), "DecodedLimit"},
		{writerSegment(writerDescriptor(0, 1), [][]byte{bytes.Repeat([]byte{'x'}, 1_048_577)}), "Spool"},
		{make([]byte, 4_269_337), "SegmentTooLarge"},
	}
	for _, p := range [][]byte{nil, []byte(" \t"), []byte("\xef\xbb\xbf\n"), []byte("x\r\n")} {
		bad = append(bad, struct {
			input []byte
			name  string
		}{writerSegment(writerDescriptor(0, 1), [][]byte{p}), "LineFraming"})
	}
	tail := writerSegment(writerDescriptor(0, 1), [][]byte{[]byte("x")})
	tail = append(tail, 0)
	bad = append(bad, struct {
		input []byte
		name  string
	}{tail, "Tail"})
	for _, tc := range bad {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		cmd := exec.CommandContext(ctx, path)
		cmd.Stdin = bytes.NewReader(tc.input)
		out := &writerCapture{limit: 5_000_141}
		stderr := &writerCapture{limit: 256}
		cmd.Stdout = out
		cmd.Stderr = stderr
		err := cmd.Run()
		cancel()
		if err == nil || out.buffer.Len() != 0 || strings.TrimSpace(stderr.buffer.String()) != tc.name {
			t.Fatal("writer failure protocol")
		}
	}
}
func TestRustWriterMutations(t *testing.T) {
	writerPath(t)
	d := writerDescriptor(0, 1)
	h, b, _ := writerSuccess(t, d, [][]byte{[]byte("x")}, "device-a")
	frame := b[48:]
	flags := frame[4]
	single := flags&32 != 0
	pos := 5
	if !single {
		pos++
	}
	width := []int{0, 2, 4, 8}[flags>>6]
	if flags>>6 == 0 && single {
		width = 1
	}
	blocks := frame[pos+width : len(frame)-4]
	noSize := append([]byte{0x28, 0xb5, 0x2f, 0xfd, 4, 0x60}, blocks...)
	noSize = append(noSize, frame[len(frame)-4:]...)
	window := append([]byte{0x28, 0xb5, 0x2f, 0xfd, (flags &^ 32), 0x88}, frame[pos:]...)
	// A one-byte single-segment size needs a two-byte field after clearing single.
	if width == 1 {
		window = []byte{0x28, 0xb5, 0x2f, 0xfd, 0x44, 0x88, 0, 0}
		window = append(window, blocks...)
		window = append(window, frame[len(frame)-4:]...)
	}
	checksum := bytes.Clone(b)
	checksum[len(checksum)-1] ^= 1
	noChecksum := bytes.Clone(b[:len(b)-4])
	noChecksum[52] &^= 4
	mismatch := bytes.Clone(b)
	mismatch[20] ^= 1
	cases := []struct {
		body []byte
		want error
	}{{checksum, ErrChecksum}, {append(bytes.Clone(b), frame...), ErrTrailingData}, {noChecksum, ErrChecksumRequired}, {append(bytes.Clone(b[:48]), noSize...), ErrContentSizeRequired}, {append(bytes.Clone(b[:48]), window...), ErrWindowLimit}, {mismatch, wire.ErrDescriptorMismatch}}
	for _, c := range cases {
		_, lines, err := writerDecode(h, c.body, "device-a")
		if !errors.Is(err, c.want) || lines != nil {
			t.Fatalf("mutation: got %v, want %v; provisional=%d", err, c.want, len(lines))
		}
	}
	if _, _, err := writerResponse([]byte("malformed")); err == nil {
		t.Fatal("malformed child accepted")
	}
	if _, _, err := writerRun(filepath.Join(t.TempDir(), "missing"), nil); err == nil {
		t.Fatal("missing executable accepted")
	}
	// Exercise the missing environment precondition in an isolated test child.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRustWriterPrecondition$")
	child.Env = append(os.Environ(), "RICEVANTA_WRITER_PRECONDITION=1", "RICEVANTA_BATCH_VECTOR=")
	out := &writerCapture{limit: 4096}
	child.Stdout = out
	child.Stderr = out
	if err := child.Run(); err == nil || !strings.Contains(out.buffer.String(), "RICEVANTA_BATCH_VECTOR") {
		t.Fatal("missing-path precondition did not fail")
	}
}
func TestRustWriterPrecondition(t *testing.T) {
	if os.Getenv("RICEVANTA_WRITER_PRECONDITION") == "1" {
		writerPath(t)
	}
}

func TestRustWriterCaptureOverflow(t *testing.T) {
	for _, pipe := range []string{"stdout", "stderr"} {
		t.Run(pipe, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRustWriterCaptureChild$")
			cmd.Env = append(os.Environ(), "RICEVANTA_WRITER_CAPTURE_PIPE="+pipe)
			out := &writerCapture{limit: 256}
			stderr := &writerCapture{limit: 256}
			cmd.Stdout = out
			cmd.Stderr = stderr
			err := cmd.Run()
			if err == nil || !strings.Contains(err.Error(), "child output bound") {
				t.Errorf("capture overflow: got %v, want child output bound", err)
			}
			if out.buffer.Len() > out.limit || stderr.buffer.Len() > stderr.limit {
				t.Errorf("capture limit bypassed: stdout=%d stderr=%d limit=256", out.buffer.Len(), stderr.buffer.Len())
			}
		})
	}
}

func TestRustWriterCaptureChild(t *testing.T) {
	var pipe *os.File
	switch os.Getenv("RICEVANTA_WRITER_CAPTURE_PIPE") {
	case "stdout":
		pipe = os.Stdout
	case "stderr":
		pipe = os.Stderr
	default:
		return
	}
	if _, err := pipe.Write(bytes.Repeat([]byte{'x'}, 1024)); err != nil {
		os.Exit(1)
	}
	// Suppress the test runner's stdout so only the selected pipe emits bytes.
	os.Exit(0)
}
