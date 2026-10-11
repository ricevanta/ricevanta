//
// Copyright (c) 2011-2019 Canonical Ltd
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package yamltokens

import (
	"strconv"
	"strings"
)

const (
	nullTag      = "!!null"
	boolTag      = "!!bool"
	strTag       = "!!str"
	intTag       = "!!int"
	floatTag     = "!!float"
	timestampTag = "!!timestamp"
	seqTag       = "!!seq"
	mapTag       = "!!map"
	mergeTag     = "!!merge"
)

// resolveImplicit keeps the pinned implicit resolver's decision order. Only the
// tag enters a Node; reflection decoding and resolved Go values are excluded.
func resolveImplicit(in string, b *Budget) (string, error) {
	switch in {
	case "true", "True", "TRUE", "false", "False", "FALSE":
		return boolTag, nil
	case "", "~", "null", "Null", "NULL":
		return nullTag, nil
	case ".nan", ".NaN", ".NAN", ".inf", ".Inf", ".INF", "+.inf", "+.Inf", "+.INF", "-.inf", "-.Inf", "-.INF":
		return floatTag, nil
	case "<<":
		return mergeTag, nil
	}
	if in[0] == '.' {
		if err := resolverReserve(b, in, 1); err != nil {
			return "", err
		}
		if _, err := strconv.ParseFloat(in, 64); err == nil {
			return floatTag, nil
		}
	} else if in[0] == '+' || in[0] == '-' || in[0] >= '0' && in[0] <= '9' {
		if timestamp(in) {
			return timestampTag, nil
		}

		plain := in
		if strings.IndexByte(in, '_') >= 0 {
			if err := b.allocation("resolver", uint64(len(in)), 1); err != nil {
				return "", err
			}
			plain = strings.ReplaceAll(in, "_", "")
		}
		if integer(plain, 0, true) || integer(plain, 0, false) {
			return intTag, nil
		}
		if yamlFloat(plain) {
			if err := resolverReserve(b, plain, 1); err != nil {
				return "", err
			}
			if _, err := strconv.ParseFloat(plain, 64); err == nil {
				return floatTag, nil
			}
		}
		for _, prefix := range []string{"0b", "-0b", "0o", "-0o"} {
			if !strings.HasPrefix(plain, prefix) {
				continue
			}
			digits := plain[len(prefix):]
			base := 2
			if prefix[len(prefix)-1] == 'o' {
				base = 8
			}
			if prefix[0] == '-' {
				// The pinned fallback prepends a minus. Two signs cannot parse.
				if len(digits) > 0 && digits[0] != '+' && digits[0] != '-' && negativeInteger(digits, base) {
					return intTag, nil
				}
			} else if integer(digits, base, true) || integer(digits, base, false) {
				return intTag, nil
			}
		}
	}
	return strTag, nil
}
func resolverReserve(b *Budget, s string, calls uint64) error {
	// strconv failure allocates NumError plus a cloned input. ParseFloat's
	// decimal scratch stays on the stack. Bases and bit sizes are fixed.
	return b.allocation("resolver", calls*(uint64(len(s))+48), calls*2)
}

// timestamp recognizes the four pinned parseTimestamp formats without creating
// time.Parse errors, quoted input copies or consulting the local time zone.
func timestamp(s string) bool {
	if len(s) < 8 || s[4] != '-' {
		return false
	}
	year := 0
	for i := 0; i < 4; i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
		year = year*10 + int(s[i]-'0')
	}
	i := 5
	number := func() (int, bool) {
		if i == len(s) || s[i] < '0' || s[i] > '9' {
			return 0, false
		}
		n := int(s[i] - '0')
		i++
		if i < len(s) && s[i] >= '0' && s[i] <= '9' {
			n = n*10 + int(s[i]-'0')
			i++
		}
		return n, true
	}
	month, ok := number()
	if !ok || month < 1 || month > 12 || i == len(s) || s[i] != '-' {
		return false
	}
	i++
	day, ok := number()
	if !ok || day < 1 {
		return false
	}
	days := [...]int{31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}
	if year%4 == 0 && (year%100 != 0 || year%400 == 0) {
		days[1] = 29
	}
	if day > days[month-1] {
		return false
	}
	if i == len(s) {
		return true
	}
	sep := s[i]
	if sep != 'T' && sep != 't' && sep != ' ' {
		return false
	}
	i++
	if sep == ' ' {
		for i < len(s) && s[i] == ' ' {
			i++
		}
	}
	hour, ok := number()
	if !ok || hour > 23 || i == len(s) || s[i] != ':' {
		return false
	}
	i++
	minute, ok := number()
	if !ok || minute > 59 || i == len(s) || s[i] != ':' {
		return false
	}
	i++
	second, ok := number()
	if !ok || second > 59 {
		return false
	}
	if i+1 < len(s) && (s[i] == '.' || s[i] == ',') && s[i+1] >= '0' && s[i+1] <= '9' {
		i++
		for i < len(s) && s[i] >= '0' && s[i] <= '9' {
			i++
		}
	}
	if sep == ' ' {
		return i == len(s)
	}
	if i < len(s) && s[i] == 'Z' {
		return i+1 == len(s)
	}
	if len(s)-i != 6 || (s[i] != '+' && s[i] != '-') || s[i+3] != ':' {
		return false
	}
	for _, j := range []int{i + 1, i + 2, i + 4, i + 5} {
		if s[j] < '0' || s[j] > '9' {
			return false
		}
	}
	return int(s[i+1]-'0')*10+int(s[i+2]-'0') <= 24 && int(s[i+4]-'0')*10+int(s[i+5]-'0') <= 60
}

// yamlFloat implements the pinned anchored expression without regexp caches.
func yamlFloat(s string) bool {
	i := 0
	if i < len(s) && (s[i] == '-' || s[i] == '+') {
		i++
	}
	start := i
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	whole := i - start
	if i < len(s) && s[i] == '.' {
		i++
		start = i
		for i < len(s) && s[i] >= '0' && s[i] <= '9' {
			i++
		}
		if whole == 0 && i == start {
			return false
		}
	} else if whole == 0 {
		return false
	}
	if i < len(s) && (s[i] == 'e' || s[i] == 'E') {
		i++
		if i < len(s) && (s[i] == '-' || s[i] == '+') {
			i++
		}
		start = i
		for i < len(s) && s[i] >= '0' && s[i] <= '9' {
			i++
		}
		if i == start {
			return false
		}
	}
	return i == len(s)
}

// integer is the tag-only form of Go 1.27.1 ParseInt/ParseUint. It keeps
// base-zero prefixes, sign rules, leading-zero octal and 64-bit range checks.
// Underscores have already been removed by the pinned resolver.
func integer(s string, base int, signed bool) bool {
	negative, hasSign := false, false
	if len(s) > 0 && (s[0] == '+' || s[0] == '-') {
		if !signed {
			return false
		}
		negative = s[0] == '-'
		hasSign = true
		s = s[1:]
	}
	if len(s) == 0 {
		return false
	}
	if base == 0 {
		base = 10
		if s[0] == '0' {
			base = 8
			if len(s) > 2 {
				switch s[1] {
				case 'b', 'B':
					base = 2
					s = s[2:]
				case 'o', 'O':
					base = 8
					s = s[2:]
				case 'x', 'X':
					base = 16
					s = s[2:]
				}
			}
		}
	}
	limit := ^uint64(0)
	if signed {
		limit = 1<<63 - 1
		if negative {
			limit = 1 << 63
		}
	}
	if !signed && hasSign {
		return false
	}
	var n uint64
	for i := 0; i < len(s); i++ {
		c := s[i]
		var digit uint64
		switch {
		case c >= '0' && c <= '9':
			digit = uint64(c - '0')
		case c >= 'a' && c <= 'f':
			digit = uint64(c - 'a' + 10)
		case c >= 'A' && c <= 'F':
			digit = uint64(c - 'A' + 10)
		default:
			return false
		}
		if digit >= uint64(base) || n > (limit-digit)/uint64(base) {
			return false
		}
		n = n*uint64(base) + digit
	}
	return true
}
func negativeInteger(digits string, base int) bool {
	// Accept the same signed range without constructing "-" + digits.
	if len(digits) == 0 {
		return false
	}
	var n uint64
	for i := 0; i < len(digits); i++ {
		c := digits[i]
		if c < '0' || c > '9' || int(c-'0') >= base {
			return false
		}
		digit := uint64(c - '0')
		if n > ((uint64(1)<<63)-digit)/uint64(base) {
			return false
		}
		n = n*uint64(base) + digit
	}
	return true
}
