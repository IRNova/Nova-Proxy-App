//go:build !windows

package main

func buildAutoStartCommand(execPath string) string {
	return execPath
}

func setAutoStartEnabled(enabled bool, command string) error {
	return nil
}
