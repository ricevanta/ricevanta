package yamltokens

import (
	"syscall"
	"unsafe"
)

func parserPeakRSS() (uint64, error) {
	// PROCESS_MEMORY_COUNTERS uses DWORD followed by pointer-sized SIZE_T fields.
	var counters struct {
		Size, Faults                                                                                 uint32
		PeakWorkingSet, WorkingSet, PeakPaged, Paged, PeakNonPaged, NonPaged, Pagefile, PeakPagefile uintptr
	}
	counters.Size = uint32(unsafe.Sizeof(counters))
	handle, err := syscall.GetCurrentProcess()
	if err != nil {
		return 0, err
	}
	get := syscall.NewLazyDLL("psapi.dll").NewProc("GetProcessMemoryInfo")
	ok, _, callErr := get.Call(uintptr(handle), uintptr(unsafe.Pointer(&counters)), uintptr(counters.Size))
	if ok == 0 {
		return 0, callErr
	}
	return uint64(counters.PeakWorkingSet), nil
}
