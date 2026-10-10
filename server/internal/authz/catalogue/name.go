package catalogue

// ValidateName checks the byte grammar without checking catalogue membership.
func ValidateName(name string) error {
	if len(name) < 5 || len(name) > 98 {
		return ErrNameFormat
	}
	tokens, length := 1, 0
	for i := 0; i < len(name); i++ {
		b := name[i]
		if b == '.' {
			if length == 0 {
				return ErrNameFormat
			}
			tokens++
			length = 0
			continue
		}
		if length == 0 {
			if b < 'a' || b > 'z' {
				return ErrNameFormat
			}
		} else if !(b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '_') {
			return ErrNameFormat
		}
		length++
		if length > 32 {
			return ErrNameFormat
		}
	}
	if tokens != 3 || length == 0 {
		return ErrNameFormat
	}
	return nil
}
