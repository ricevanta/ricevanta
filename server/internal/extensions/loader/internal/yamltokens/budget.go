package yamltokens

import "unsafe"

func (p *yaml_parser_t) fail(err error) bool {
	if p.guardErr == nil {
		p.guardErr = err
	}
	p.error = yaml_SCANNER_ERROR
	return false
}

// appendBytes checks length and clamps capacity before each scratch-buffer growth.
func appendBytes(p *yaml_parser_t, dst []byte, src ...byte) []byte {
	if p.guardErr != nil {
		return dst
	}
	if len(src) > maxBytes-len(dst) {
		p.fail(ErrLimit)
		return dst
	}
	n := len(dst) + len(src)
	if n > cap(dst) {
		c := max(32, cap(dst)*2)
		if c < n {
			c = n
		}
		if c > maxBytes {
			c = maxBytes
		}
		if !reserveParser(p, "scratch", uint64(c), 1) {
			return dst
		}
		next := make([]byte, len(dst), c)
		copy(next, dst)
		dst = next
	}
	return append(dst, src...)
}

// Callers prove length below limit before calling; capacity never exceeds limit.
func boundedAppend[T any](p *yaml_parser_t, family string, dst []T, v T, limit int) []T {
	if len(dst) == cap(dst) {
		c := min(limit, max(16, cap(dst)*2))

		if !reserveParser(p, family, uint64(c)*uint64(unsafe.Sizeof(v)), 1) {
			return dst
		}
		next := make([]T, len(dst), c)
		copy(next, dst)
		dst = next
	}
	return append(dst, v)
}

func appendValue(p *yaml_parser_t, dst []byte, src ...byte) []byte {
	if len(src) > maxBytes-p.tokenBytes-len(dst) {
		p.fail(ErrLimit)
		return dst
	}
	return appendBytes(p, dst, src...)
}

func readValue(p *yaml_parser_t, dst []byte) []byte {
	if width(p.buffer[p.buffer_pos]) > maxBytes-p.tokenBytes-len(dst) {
		p.fail(ErrLimit)
	}
	return read(p, dst)
}
func readLineValue(p *yaml_parser_t, dst []byte) []byte {
	n := 1
	if is_break(p.buffer, p.buffer_pos) && p.buffer[p.buffer_pos] == 0xe2 {
		n = 3
	}
	if n > maxBytes-p.tokenBytes-len(dst) {
		p.fail(ErrLimit)
	}
	return read_line(p, dst)
}

// Budget records cumulative allocator charges. Failed reservations leave it unchanged.
type Budget struct {
	bytes, objects uint64
	failFamily     string // Test injection, inert in normal calls.
	failObjects    bool
	injected       bool
	failAt, hits   int
	begun          bool
}

func newBudget() *Budget { return &Budget{} }
func (b *Budget) Reserve(bytes, objects uint64) error {
	if bytes > (64<<20)-b.bytes || objects > 1000000-b.objects {
		return ErrLimit
	}
	b.bytes += bytes
	b.objects += objects
	return nil
}

// Allocation rounds each object to at most twice its size plus 32 bytes below
// 32 KiB, or adds at most one 8 KiB page above that threshold.
func (b *Budget) allocation(family string, bytes, objects uint64) error {
	if b.failFamily == family {
		b.hits++
	}
	if b.failFamily == family && !b.injected && (b.failAt == 0 || b.failAt == b.hits) {
		b.injected = true
		if b.failObjects {
			return b.Reserve(0, 1000001)
		}
		return b.Reserve(64<<20+1, 0)
	}
	if objects > 1000000 || bytes > 64<<20 {
		return ErrLimit
	}
	rounded := bytes*2 + objects*32
	if objects == 1 && bytes >= 32768 {
		rounded = bytes + 8192
	}
	return b.Reserve(rounded, objects)
}
func reserveParser(p *yaml_parser_t, family string, bytes, objects uint64) bool {
	if p.guardErr != nil {
		return false
	}
	if p.budget == nil {
		p.budget = newBudget()
	}
	if err := p.budget.allocation(family, bytes, objects); err != nil {
		return p.fail(err)
	}
	return true
}
func liveSimpleKey(p *yaml_parser_t, token int) (int, bool) {
	for i := len(p.simple_keys) - 1; i >= 0; i-- {
		if p.simple_keys[i].possible && p.simple_keys[i].token_number == token {
			return i, true
		}
	}
	return 0, false
}

func (b *Budget) begin() error {
	if b.begun {
		return nil
	}
	if err := b.allocation("entry", 8192, 8); err != nil {
		return err
	}
	b.begun = true
	return nil
}
