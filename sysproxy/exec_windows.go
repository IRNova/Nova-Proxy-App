// Third-party notice: this file contains material shared with historical
// MIT-licensed SniShaper source. The following grant covers that material,
// without assigning other authors' contributions to SniShaper.
//
// MIT License
//
// Copyright (c) 2026 SniShaper
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package sysproxy

import (
	"os/exec"
	"syscall"
)

// hideWindow configures the command to run in a hidden window
func hideWindow(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.HideWindow = true
}

// runHiddenCommand runs a command with the window hidden
func runHiddenCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	hideWindow(cmd)
	return cmd.Run()
}

// outputHiddenCommand runs a command with window hidden and returns the output
func outputHiddenCommand(name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	hideWindow(cmd)
	return cmd.Output()
}

// startHiddenCommand starts a command with the window hidden
func startHiddenCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	hideWindow(cmd)
	return cmd.Start()
}
