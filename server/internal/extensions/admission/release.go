package admission

import "strings"

// compareRelease compares schema-valid, bounded versions for automatic release
// authority only. Numeric fields compare without machine-integer conversion.
// Package identity elsewhere remains exact string equality.
func compareRelease(a, b string) int {
	ac, ap, ah := strings.Cut(a, "-")
	bc, bp, bh := strings.Cut(b, "-")
	an, bn := strings.Split(ac, "."), strings.Split(bc, ".")
	numeric := func(x, y string) int {
		if len(x) < len(y) {
			return -1
		}
		if len(x) > len(y) {
			return 1
		}
		return strings.Compare(x, y)
	}
	for i := range an {
		if c := numeric(an[i], bn[i]); c != 0 {
			return c
		}
	}
	if !ah && !bh {
		return 0
	}
	if !ah {
		return 1
	}
	if !bh {
		return -1
	}
	isNumeric := func(s string) bool {
		for i := range s {
			if s[i] < '0' || s[i] > '9' {
				return false
			}
		}
		return true
	}
	ai, bi := strings.Split(ap, "."), strings.Split(bp, ".")
	for i := 0; i < len(ai) && i < len(bi); i++ {
		x, y := ai[i], bi[i]
		xn, yn := isNumeric(x), isNumeric(y)
		var c int
		switch {
		case xn && yn:
			c = numeric(x, y)
		case xn:
			c = -1
		case yn:
			c = 1
		default:
			c = strings.Compare(x, y)
		}
		if c != 0 {
			return c
		}
	}
	if len(ai) < len(bi) {
		return -1
	}
	if len(ai) > len(bi) {
		return 1
	}
	return 0
}
