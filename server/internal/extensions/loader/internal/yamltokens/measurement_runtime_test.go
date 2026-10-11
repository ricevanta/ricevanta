package yamltokens

import (
	"runtime"
	"sync"
)

// prepareMeasurementRuntime exercises thread creation without candidate work.
// Both helpers unlock and exit before the measurement goroutine continues.
func prepareMeasurementRuntime() {
	ready := make(chan struct{}, 2)
	release := make(chan struct{})
	var helpers sync.WaitGroup
	helpers.Add(2)
	for range 2 {
		go func() {
			defer helpers.Done()
			runtime.LockOSThread()
			ready <- struct{}{}
			<-release
			runtime.UnlockOSThread()
		}()
	}
	<-ready
	<-ready
	close(release)
	helpers.Wait()
}
