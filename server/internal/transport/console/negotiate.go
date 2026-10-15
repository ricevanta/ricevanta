package console

import "strings"

// parseQ parses an RFC 9110 qvalue into thousandths. A value outside the
// grammar ( "0" [ "." 0*3DIGIT ] / "1" [ "." 0*3("0") ] ) yields 0, so a
// malformed weight never makes a coding acceptable.
func parseQ(v string) int {
	if v == "" || len(v) > 5 {
		return 0
	}
	whole, frac, dot := strings.Cut(v, ".")
	if !dot && frac != "" {
		return 0
	}
	if len(frac) > 3 {
		return 0
	}
	for i := 0; i < len(frac); i++ {
		if frac[i] < '0' || frac[i] > '9' {
			return 0
		}
	}
	switch whole {
	case "1":
		if strings.Trim(frac, "0") != "" {
			return 0
		}
		return 1000
	case "0":
		n := 0
		for i := 0; i < 3; i++ {
			n *= 10
			if i < len(frac) {
				n += int(frac[i] - '0')
			}
		}
		return n
	}
	return 0
}

// codingWeights returns the weights of br and gzip in an Accept-Encoding
// value per RFC 9110 section 12.5.3: a listed coding takes its own weight, an
// unlisted one the weight of "*", and a coding matched by neither is not
// acceptable. The first listing of a coding counts; x-gzip is gzip.
func codingWeights(header string) (br, gz int) {
	br, gz, star := -1, -1, -1
	for _, part := range strings.Split(header, ",") {
		fields := strings.Split(part, ";")
		name := strings.ToLower(strings.TrimSpace(fields[0]))
		if name == "" {
			continue
		}
		q := 1000
		for _, p := range fields[1:] {
			k, v, ok := strings.Cut(strings.TrimSpace(p), "=")
			if ok && strings.EqualFold(strings.TrimSpace(k), "q") {
				q = parseQ(strings.TrimSpace(v))
			}
		}
		switch name {
		case "br":
			if br < 0 {
				br = q
			}
		case "gzip", "x-gzip":
			if gz < 0 {
				gz = q
			}
		case "*":
			if star < 0 {
				star = q
			}
		}
	}
	if star < 0 {
		star = 0
	}
	if br < 0 {
		br = star
	}
	if gz < 0 {
		gz = star
	}
	return br, gz
}

// choose picks br, gzip or identity ("") among the available sidecars:
// the acceptable coding with the highest weight wins, br on a tie, and the
// uncoded bytes are sent when no available coding is acceptable.
func choose(header string, hasBr, hasGz bool) string {
	br, gz := codingWeights(header)
	if !hasBr {
		br = 0
	}
	if !hasGz {
		gz = 0
	}
	switch {
	case br > 0 && br >= gz:
		return "br"
	case gz > 0:
		return "gzip"
	}
	return ""
}

// NegotiateEncoding returns the coding chosen for an Accept-Encoding value
// when both sidecars exist: "br", "gzip" or "" for identity.
func NegotiateEncoding(header string) string { return choose(header, true, true) }

// acceptsHTML reports whether the Accept values admit text/html: the most
// specific matching range (text/html, then text/*, then */*) decides, and a
// zero weight excludes. An absent field accepts everything.
func acceptsHTML(values []string) bool {
	if len(values) == 0 {
		return true
	}
	best, weight := 0, 0
	for _, part := range strings.Split(strings.Join(values, ","), ",") {
		fields := strings.Split(part, ";")
		rng := strings.ToLower(strings.TrimSpace(fields[0]))
		spec := 0
		switch rng {
		case "text/html":
			spec = 3
		case "text/*":
			spec = 2
		case "*/*":
			spec = 1
		default:
			continue
		}
		if spec <= best {
			continue
		}
		q := 1000
		for _, p := range fields[1:] {
			k, v, ok := strings.Cut(strings.TrimSpace(p), "=")
			if ok && strings.EqualFold(strings.TrimSpace(k), "q") {
				q = parseQ(strings.TrimSpace(v))
			}
		}
		best, weight = spec, q
	}
	return best > 0 && weight > 0
}
