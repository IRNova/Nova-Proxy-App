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
