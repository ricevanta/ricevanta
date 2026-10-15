package body

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"
)

// Shape generators shared by the walker tests, BenchmarkWalk and the cost-model
// harness. Each returns NDJSON lines with LF whose total length per line,
// including LF, is lineBytes. Every line starts with valid identity fields for
// sequence i from 0, so a descriptor starting at sequence 0 accepts them.

func shapeUUID(n uint64) string {
	var b [16]byte
	binary.BigEndian.PutUint64(b[0:8], 0x0190_0000_0000_7000|(n>>12)&0xfff)
	b[6] = 0x70 | byte((n>>8)&0x0f)
	b[7] = byte(n)
	b[8] = 0x80 | byte(n>>16)&0x3f
	binary.BigEndian.PutUint32(b[12:16], uint32(n))
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", binary.BigEndian.Uint32(b[0:4]), binary.BigEndian.Uint16(b[4:6]), binary.BigEndian.Uint16(b[6:8]), binary.BigEndian.Uint16(b[8:10]), b[10:16])
}

func shapePrefix(seq uint64) string {
	return fmt.Sprintf(`{"metadata":{"uid":"%s","sequence":%d},"device":{"uid":"device-a"}`, shapeUUID(seq), seq)
}

// shapeLines writes lines lines. member(k) returns the k-th member text with its
// leading comma, or "" to stop; open and close wrap the members after the prefix.
func shapeLines(lines, lineBytes int, open string, member func(k int) string, close string) []byte {
	var out bytes.Buffer
	out.Grow(lines * lineBytes)
	for i := range lines {
		p := shapePrefix(uint64(i))
		out.WriteString(p)
		out.WriteString(open)
		used := len(p) + len(open)
		for k := 0; ; k++ {
			m := member(k)
			if m == "" || used+len(m)+len(close)+2 > lineBytes {
				break
			}
			out.WriteString(m)
			used += len(m)
		}
		out.WriteString(close)
		used += len(close)
		for used+2 < lineBytes {
			out.WriteByte(' ')
			used++
		}
		out.WriteString("}\n")
	}
	return out.Bytes()
}

const shapeBase62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

func shapeKey3(k int) string {
	return string([]byte{shapeBase62[k/3844%62], shapeBase62[k/62%62], shapeBase62[k%62]})
}

// genFlat: distinct "kN":0 members.
func genFlat(lines, lineBytes int) []byte {
	return shapeLines(lines, lineBytes, "", func(k int) string { return fmt.Sprintf(`,"k%d":0`, k) }, "")
}

// genNested: distinct "kN":{"a":0} members.
func genNested(lines, lineBytes int) []byte {
	return shapeLines(lines, lineBytes, "", func(k int) string { return fmt.Sprintf(`,"k%d":{"a":0}`, k) }, "")
}

// genDense: distinct 3-byte names with zero values, 8 bytes per member.
func genDense(lines, lineBytes int) []byte {
	return shapeLines(lines, lineBytes, "", func(k int) string { return `,"` + shapeKey3(k) + `":0` }, "")
}

// genDenseNested: distinct 3-byte names holding {"a":0}.
func genDenseNested(lines, lineBytes int) []byte {
	return shapeLines(lines, lineBytes, "", func(k int) string { return `,"` + shapeKey3(k) + `":{"a":0}` }, "")
}

// genArrayObjs: one array of {"":0}, 7 bytes per member.
func genArrayObjs(lines, lineBytes int) []byte {
	return shapeLines(lines, lineBytes, `,"a":[{"":0}`, func(int) string { return `,{"":0}` }, "]")
}

var singleCharObject = func() string {
	var b strings.Builder
	b.WriteString(",{")
	first := true
	for c := 0x20; c <= 0x7f; c++ {
		if c == '"' || c == '\\' {
			continue
		}
		if !first {
			b.WriteByte(',')
		}
		first = false
		b.WriteString(`"` + string(rune(c)) + `":0`)
	}
	b.WriteByte('}')
	return b.String()
}()

// genSingleChar: arrays of objects holding all 94 one-byte names.
func genSingleChar(lines, lineBytes int) []byte {
	return shapeLines(lines, lineBytes, `,"a":[{}`, func(int) string { return singleCharObject }, "]")
}

// genRandom3: one object of distinct 3-byte names in a fixed pseudo-random order.
func genRandom3(lines, lineBytes int) []byte {
	used := len(shapePrefix(0)) + 6
	n := max((lineBytes-used-3-16)/8, 1)
	perm := make([]int, n)
	for k := range perm {
		perm[k] = k
	}
	x := uint64(1)
	for k := n - 1; k > 0; k-- {
		x ^= x << 13
		x ^= x >> 7
		x ^= x << 17
		j := int(x % uint64(k+1))
		perm[k], perm[j] = perm[j], perm[k]
	}
	return shapeLines(lines, lineBytes, `,"z":{"`+shapeKey3(perm[0])+`":0`, func(k int) string {
		if k+1 >= n {
			return ""
		}
		return `,"` + shapeKey3(perm[k+1]) + `":0`
	}, "}")
}

// genNumbers: one array of zeros.
func genNumbers(lines, lineBytes int) []byte {
	return shapeLines(lines, lineBytes, `,"a":[0`, func(int) string { return ",0" }, "]")
}

// genStrings: one long string value.
func genStrings(lines, lineBytes int) []byte {
	return shapeLines(lines, lineBytes, `,"s":"`, func(k int) string { return string(rune('a' + k%26)) }, `"`)
}

// genPrefix: names sharing a 1,000-byte prefix.
func genPrefix(lines, lineBytes int) []byte {
	shared := strings.Repeat("p", 1000)
	return shapeLines(lines, lineBytes, "", func(k int) string { return fmt.Sprintf(`,"%s%06d":0`, shared, k) }, "")
}

// genBadID: lines whose metadata.uid fails eventid.Parse.
func genBadID(lines int) []byte {
	var out bytes.Buffer
	for i := range lines {
		fmt.Fprintf(&out, `{"metadata":{"uid":"x","sequence":%d},"device":{"uid":"device-a"}}`+"\n", i)
	}
	return out.Bytes()
}

// genMinOK: minimal valid lines.
func genMinOK(lines int) []byte {
	var out bytes.Buffer
	for i := range lines {
		out.WriteString(shapePrefix(uint64(i)) + "}\n")
	}
	return out.Bytes()
}

// genRealistic: an OCSF process_activity event of about 1.76 KB with 70 members.
func genRealistic(lines int) []byte {
	var out bytes.Buffer
	for i := range lines {
		seq := uint64(i)
		fmt.Fprintf(&out, `{"metadata":{"uid":"%s","sequence":%d,"version":"1.9.0","product":{"name":"Ricevanta","vendor_name":"Ricevanta","version":"0.1.0"},"profiles":["host"],"log_name":"edr","logged_time":1760000000000,"extensions":[{"name":"ricevanta","uid":"999","version":"1.0.0"}]},"device":{"uid":"device-a","type_id":2,"type":"Desktop","hostname":"host-%04d.example.com","os":{"name":"Linux","type_id":200,"version":"6.18.44"},"groups":[{"name":"engineering","uid":"g-1"}]},"activity_id":1,"activity_name":"Launch","category_uid":1,"category_name":"System Activity","class_uid":1007,"class_name":"Process Activity","type_uid":100701,"time":%d,"severity_id":1,"severity":"Informational","status_id":1,"actor":{"process":{"pid":%d,"uid":"p-%d","name":"bash","cmd_line":"/bin/bash -c ls -la /var/log","file":{"name":"bash","path":"/usr/bin/bash","type_id":1,"hashes":[{"algorithm_id":3,"algorithm":"SHA-256","value":"%064x"}]},"user":{"uid":"1000","name":"alice","type_id":1}},"session":{"uid":"s-%d","is_remote":false}},"process":{"pid":%d,"uid":"p-%d","name":"ls","cmd_line":"ls -la /var/log","file":{"name":"ls","path":"/usr/bin/ls","type_id":1,"size":142144,"hashes":[{"algorithm_id":3,"algorithm":"SHA-256","value":"%064x"}]},"user":{"uid":"1000","name":"alice","type_id":1},"parent_process":{"pid":%d,"uid":"p-%d","name":"bash"},"created_time":%d,"integrity_id":1},"observables":[{"name":"process.file.path","type_id":7,"value":"/usr/bin/ls"},{"name":"actor.process.file.path","type_id":7,"value":"/usr/bin/bash"}],"unmapped":{"ricevanta.sensor":"ebpf","ricevanta.rule_matches":[]}}`+"\n",
			shapeUUID(seq), seq, i%9999, 1760000000000+int64(i)*17, 1000+i, i, uint64(i)*0x9e3779b97f4a7c15, i, 2000+i, i+1, uint64(i)*0x6a09e667f3bcc909, 1000+i, i, 1760000000000+int64(i)*17-5)
	}
	return out.Bytes()
}

// dupEmptyLine is one object of repeated empty names, the most members a
// 1 MiB line can hold (5 bytes each); it fails as a duplicate.
func dupEmptyLine() []byte {
	var b bytes.Buffer
	b.WriteString(`{"":0`)
	for b.Len()+5+1 <= MaxLineBytes {
		b.WriteString(`,"":0`)
	}
	b.WriteString("}")
	return b.Bytes()
}

func firstLine(plain []byte) []byte {
	return plain[:bytes.IndexByte(plain, '\n')]
}

type walkShape struct {
	name string
	gen  func(lines, lineBytes int) []byte
}

var walkShapes = []walkShape{
	{"flat", genFlat}, {"nested", genNested}, {"dense", genDense}, {"densenested", genDenseNested},
	{"arrayobjs", genArrayObjs}, {"singlechar", genSingleChar}, {"random3", genRandom3},
	{"numbers", genNumbers}, {"strings", genStrings}, {"prefix", genPrefix},
}

// tokenFields and tokenWalkFields keep the replaced encoding/json token walk
// as the benchmark reference.
type tokenFields struct {
	metadata, device         bool
	uid, sequence, deviceUID any
}
type tokenObject struct {
	object, keyNext bool
	key             string
	scope           uint8
	names           map[string]struct{}
}

func tokenWalkFields(raw []byte) (tokenFields, bool) {
	var fields tokenFields
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	stack := make([]tokenObject, 0, MaxJSONDepth)
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fields, false
		}
		delimiter, isDelimiter := token.(json.Delim)
		if isDelimiter && (delimiter == '}' || delimiter == ']') {
			stack = stack[:len(stack)-1]
			continue
		}
		var scope uint8
		var key string
		if len(stack) > 0 {
			parent := &stack[len(stack)-1]
			if parent.object && parent.keyNext {
				name := token.(string)
				if _, exists := parent.names[name]; exists {
					return fields, false
				}
				parent.names[name] = struct{}{}
				var recognized []string
				switch parent.scope {
				case 1:
					recognized = []string{"metadata", "device"}
				case 2:
					recognized = []string{"uid", "sequence"}
				case 3:
					recognized = []string{"uid"}
				}
				for _, canonical := range recognized {
					if name != canonical && strings.EqualFold(name, canonical) {
						return fields, false
					}
				}
				parent.key, parent.keyNext = name, false
				continue
			}
			scope, key = parent.scope, parent.key
			parent.keyNext = parent.object
			if parent.object {
				switch {
				case scope == 2 && key == "uid":
					fields.uid = token
				case scope == 2 && key == "sequence":
					fields.sequence = token
				case scope == 3 && key == "uid":
					fields.deviceUID = token
				}
			} else {
				scope, key = 0, ""
			}
		}
		if isDelimiter {
			child := uint8(0)
			if len(stack) == 0 {
				child = 1
			} else if scope == 1 && delimiter == '{' && (key == "metadata" || key == "device") {
				child = map[string]uint8{"metadata": 2, "device": 3}[key]
				fields.metadata = fields.metadata || key == "metadata"
				fields.device = fields.device || key == "device"
			}
			state := tokenObject{object: delimiter == '{', keyNext: delimiter == '{', scope: child}
			if state.object {
				state.names = make(map[string]struct{})
			}
			stack = append(stack, state)
		}
	}
	return fields, true
}

func hostileWalkLines() []struct {
	name string
	line []byte
} {
	const MiB = 1 << 20
	return []struct {
		name string
		line []byte
	}{
		{"flat", firstLine(genFlat(1, MiB))},
		{"dense", firstLine(genDense(1, MiB))},
		{"densenested", firstLine(genDenseNested(1, MiB))},
		{"arrayobjs", firstLine(genArrayObjs(1, MiB))},
		{"singlechar", firstLine(genSingleChar(1, MiB))},
		{"random3", firstLine(genRandom3(1, MiB))},
		{"dupempty", dupEmptyLine()},
		{"prefix", firstLine(genPrefix(1, MiB))},
		{"realistic", firstLine(genRealistic(1))},
	}
}

// BenchmarkWalk compares the lean walker with the replaced token walk on the
// hostile shapes. Each lean run reuses one per-call walker, as Decode does.
func BenchmarkWalk(b *testing.B) {
	for _, c := range hostileWalkLines() {
		if !validLineJSON(c.line) {
			b.Fatalf("%s: invalid line", c.name)
		}
		b.Run("lean/"+c.name, func(b *testing.B) {
			w := newLineWalker(MaxLineBytes)
			b.ReportAllocs()
			b.SetBytes(int64(len(c.line)))
			for b.Loop() {
				w.walkFields(c.line)
			}
		})
		b.Run("token/"+c.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(c.line)))
			for b.Loop() {
				tokenWalkFields(c.line)
			}
		})
	}
}
