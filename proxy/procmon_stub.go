//go:build !windows

package proxy

func newTCPFetcher(proxyPort int) func() (map[string]int32, error) {
	return func() (map[string]int32, error) {
		return make(map[string]int32), nil
	}
}

func getAllProcessPIDs() []int32 {
	return nil
}
