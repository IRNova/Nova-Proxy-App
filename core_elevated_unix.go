//go:build !windows

package main

import "os"

// isProcessElevated checks if the current process runs with root privileges
func isProcessElevated() bool {
	return os.Geteuid() == 0
}
