//go:build windows

package main

import (
	"os/exec"
)

// isProcessElevated checks if the current process runs with admin privileges on Windows
func isProcessElevated() bool {
	cmd := exec.Command("net", "session")
	return cmd.Run() == nil
}
