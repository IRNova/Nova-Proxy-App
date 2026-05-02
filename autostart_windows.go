//go:build windows

package main

import (
	"strings"
	"syscall"

	"golang.org/x/sys/windows/registry"
)

const (
	autoStartRegistryPath = `Software\Microsoft\Windows\CurrentVersion\Run`
	autoStartValueName    = "NovaProxy"
)

func buildAutoStartCommand(execPath string) string {
	trimmed := strings.TrimSpace(execPath)
	if trimmed == "" {
		return ""
	}
	return syscall.EscapeArg(trimmed) + " --startup"
}

func setAutoStartEnabled(enabled bool, command string) error {
	key, _, err := registry.CreateKey(registry.CURRENT_USER, autoStartRegistryPath, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer key.Close()

	if !enabled {
		err = key.DeleteValue(autoStartValueName)
		if err == registry.ErrNotExist {
			return nil
		}
		return err
	}

	return key.SetStringValue(autoStartValueName, command)
}
