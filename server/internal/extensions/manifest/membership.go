package manifest

// sortStrings sorts private scratch without allocating or moving string bytes.
func sortStrings(values []string) {
	for root := len(values) / 2; root > 0; {
		root--
		siftStrings(values, root, len(values))
	}
	for end := len(values) - 1; end > 0; end-- {
		values[0], values[end] = values[end], values[0]
		siftStrings(values, 0, end)
	}
}

// siftStrings restores a max heap in the half-open prefix [0,end).
func siftStrings(values []string, root, end int) {
	for root < end/2 {
		child := root*2 + 1
		if child+1 < end && values[child] < values[child+1] {
			child++
		}
		if values[root] >= values[child] {
			return
		}
		values[root], values[child] = values[child], values[root]
		root = child
	}
}

// findString returns the first matching index, or the insertion index.
func findString(values []string, key string) (index int, found bool) {
	lo, hi := 0, len(values)
	for lo < hi {
		mid := lo + (hi-lo)/2
		if values[mid] < key {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	return lo, lo < len(values) && values[lo] == key
}
