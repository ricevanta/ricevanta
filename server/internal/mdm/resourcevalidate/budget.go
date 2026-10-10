package resourcevalidate

import (
	"math"
	"sort"
	"unicode/utf8"
)

func keys(m map[string]any) []string {
	a := make([]string, 0, len(m))
	for k := range m {
		a = append(a, k)
	}
	sort.Strings(a)
	return a
}

// scanKeys selects the next bounded batch in byte-lexicographic order. Rescan
// large maps rather than allocate storage proportional to untrusted map size.
// Shape checks may use keys only after scan has admitted the whole tree.
func scanKeys(m map[string]any, after string, started bool) []string {
	const batch = 128
	a := make([]string, 0, min(len(m), batch))
	for k := range m {
		if started && k <= after {
			continue
		}
		if len(a) == batch && k >= a[len(a)-1] {
			continue
		}
		i := sort.SearchStrings(a, k)
		if len(a) < batch {
			a = append(a, "")
		}
		copy(a[i+1:], a[i:len(a)-1])
		a[i] = k
	}
	return a
}

// scan bounds traversal before any shape check or size calculation.
func scan(root map[string]any) error {
	if root == nil {
		return nil
	}
	count, raw := 0, 0
	var walk func(any, location, int) error
	walk = func(v any, p location, depth int) error {
		count++
		if count > 100000 {
			return failure(ErrLimit, p, "budget")
		}
		switch x := v.(type) {
		case map[string]any:
			if x == nil {
				return failure(ErrInput, p, "input")
			}
			depth++
			if depth > 32 {
				return failure(ErrLimit, p, "budget")
			}
			after, started := "", false
			for {
				batch := scanKeys(x, after, started)
				if len(batch) == 0 {
					break
				}
				for _, k := range batch {
					q := p.child(k)
					if err := walk(k, q, depth); err != nil {
						return err
					}
					if err := walk(x[k], q, depth); err != nil {
						return err
					}
				}
				after, started = batch[len(batch)-1], true
			}
		case []any:
			if x == nil {
				return failure(ErrInput, p, "input")
			}
			depth++
			if depth > 32 {
				return failure(ErrLimit, p, "budget")
			}
			for i, y := range x {
				if err := walk(y, p.child(i), depth); err != nil {
					return err
				}
			}
		case string:
			if !utf8.ValidString(x) {
				return failure(ErrInput, p, "input")
			}
			raw += len(x)
			if raw > 2097152 {
				return failure(ErrLimit, p, "budget")
			}
		case float64:
			if math.IsNaN(x) || math.IsInf(x, 0) || math.Abs(x) > 9007199254740991 {
				return failure(ErrInput, p, "input")
			}
		case nil, bool:
		default:
			return failure(ErrInput, p, "input")
		}
		return nil
	}
	return walk(root, nil, 0)
}

// charge operates only on trees admitted by scan. Number spellings cost 24 bytes.
func charge(v any) int {
	switch x := v.(type) {
	case nil:
		return 4
	case bool:
		if x {
			return 4
		}
		return 5
	case float64:
		return 24
	case string:
		n := 2
		for _, r := range x {
			switch {
			case r < 32:
				n += 6
			case r == '"' || r == '\\':
				n += 2
			default:
				n += utf8.RuneLen(r)
			}
		}
		return n
	case []any:
		n := 2 + max(0, len(x)-1)
		for _, y := range x {
			n += charge(y)
		}
		return n
	case map[string]any:
		n := 2 + max(0, len(x)-1)
		for k, y := range x {
			n += charge(k) + 1 + charge(y)
		}
		return n
	}
	return 0
}
