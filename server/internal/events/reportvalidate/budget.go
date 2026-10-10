package reportvalidate

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

// scan bounds traversal before any shape check or size calculation.
func scan(root map[string]any) error {
	if root == nil {
		return nil
	}
	count, raw := 0, 0
	var walk func(any, location, int) error
	walk = func(v any, p location, depth int) error {
		count = min(8193, count+1)
		if count > 8192 {
			return failure(ErrLimit, p, "budget")
		}
		switch x := v.(type) {
		case map[string]any:
			if x == nil {
				return failure(ErrInput, p, "input")
			}
			depth++
			if depth > 16 {
				return failure(ErrLimit, p, "budget")
			}
			if len(x) > (8192-count)/2 {
				return failure(ErrLimit, p, "budget")
			}
			total := 0
			for k := range x {
				if len(k) > 131072-raw-total {
					return failure(ErrLimit, p, "budget")
				}
				total += len(k)
			}
			for _, k := range keys(x) {
				q := p.child(k)
				if e := walk(k, q, depth); e != nil {
					return e
				}
				if e := walk(x[k], q, depth); e != nil {
					return e
				}
			}
		case []any:
			if x == nil {
				return failure(ErrInput, p, "input")
			}
			depth++
			if depth > 16 {
				return failure(ErrLimit, p, "budget")
			}
			if len(x) > 8192-count {
				return failure(ErrLimit, p, "budget")
			}
			for i, y := range x {
				if err := walk(y, p.child(i), depth); err != nil {
					return err
				}
			}
		case string:
			if len(x) > 131072-raw {
				return failure(ErrLimit, p, "budget")
			}
			raw += len(x)
			if !utf8.ValidString(x) {
				return failure(ErrInput, p, "input")
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
// Saturation is above the maximum admitted tree charge, so valid preflight
// trees retain their exact charge without risking counter overflow.
func addCharge(a, b int) int {
	const cap = 1048576
	if b >= cap-a {
		return cap
	}
	return a + b
}

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
				n = addCharge(n, 6)
			case r == '"' || r == '\\':
				n = addCharge(n, 2)
			default:
				n = addCharge(n, utf8.RuneLen(r))
			}
		}
		return n
	case []any:
		n := 2 + max(0, len(x)-1)
		for _, y := range x {
			n = addCharge(n, charge(y))
		}
		return n
	case map[string]any:
		n := 2 + max(0, len(x)-1)
		for k, y := range x {
			n = addCharge(n, addCharge(charge(k), addCharge(1, charge(y))))
		}
		return n
	}
	return 0
}
