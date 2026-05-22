//go:build windows

package main

import (
	"fmt"
	"os/exec"
	"strings"
	"syscall"
)

func startCoreProcess(execPath string, elevated bool) error {
	if !elevated {
		cmd := exec.Command(execPath, "--core")
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		return cmd.Start()
	}

	escape := func(s string) string {
		return strings.ReplaceAll(s, "'", "''")
	}

	psScript := fmt.Sprintf(
		"$p = Start-Process -FilePath '%s' -ArgumentList @('--core') -Verb RunAs -WindowStyle Hidden -PassThru; if ($null -eq $p) { exit 1 }",
		escape(execPath),
	)

	cmd := exec.Command("powershell", "-NoProfile", "-Command", psScript)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.Run()
}
