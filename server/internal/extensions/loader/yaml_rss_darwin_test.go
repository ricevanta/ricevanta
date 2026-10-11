package loader

import "syscall"

func parserPeakRSS() (uint64, error) {
	var r syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &r); err != nil {
		return 0, err
	}
	return uint64(r.Maxrss), nil
}
