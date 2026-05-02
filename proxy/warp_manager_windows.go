//go:build windows
package proxy

import (
	"os/exec"
	"syscall"
)

func (m *WarpManager) setupHiddenWindow(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.HideWindow = true
}
