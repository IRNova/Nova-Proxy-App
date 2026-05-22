//go:build !windows

package main

import (
	"os/exec"
)

func startCoreProcess(execPath string, _ bool) error {
	return exec.Command(execPath, "--core").Start()
}
