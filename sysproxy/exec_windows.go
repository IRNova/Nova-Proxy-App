package sysproxy

import (
	"os/exec"
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
