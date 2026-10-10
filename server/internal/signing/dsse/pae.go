package dsse

import "strconv"

func pae(typ PayloadType, payload []byte) []byte {
	prefix := "DSSEv1 " + strconv.Itoa(len(typ)) + " " + string(typ) + " " + strconv.Itoa(len(payload)) + " "
	out := make([]byte, len(prefix)+len(payload))
	copy(out, prefix)
	copy(out[len(prefix):], payload)
	return out
}
