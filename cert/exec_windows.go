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

package cert

import (
	"fmt"
	"os/exec"
	"strings"
	"syscall"
)

// hideWindow 设置命令在隐藏窗口中运行
func hideWindow(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.HideWindow = true
}

// runHiddenCommand 运行命令并隐藏窗口
func runHiddenCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	hideWindow(cmd)
	return cmd.Run()
}

// outputHiddenCommand 运行命令并隐藏窗口，返回输出
func outputHiddenCommand(name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	hideWindow(cmd)
	return cmd.Output()
}

// startHiddenCommand 启动命令并隐藏窗口
func startHiddenCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	hideWindow(cmd)
	return cmd.Start()
}
// startVisibleCommand 启动命令并显示窗口
func startVisibleCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	// 不设置 HideWindow = true
	return cmd.Start()
}

func runElevatedCommand(name string, args ...string) error {
	escape := func(s string) string {
		return strings.ReplaceAll(s, "'", "''")
	}

	quotedArgs := make([]string, 0, len(args))
	for _, arg := range args {
		quotedArgs = append(quotedArgs, fmt.Sprintf("'%s'", escape(arg)))
	}

	psScript := fmt.Sprintf(
		"$p = Start-Process -FilePath '%s' -ArgumentList @(%s) -Verb RunAs -Wait -PassThru; exit $p.ExitCode",
		escape(name),
		strings.Join(quotedArgs, ","),
	)

	cmd := exec.Command("powershell", "-NoProfile", "-Command", psScript)
	return cmd.Run()
}
