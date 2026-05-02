//go:build !windows
package proxy

import (
	"os/exec"
)

func (m *WarpManager) setupHiddenWindow(cmd *exec.Cmd) {
	// Non-Windows systems require no special handling
}
