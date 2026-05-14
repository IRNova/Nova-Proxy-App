package proxy

import (
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

// FindProcessByPort returns the PID occupying the specified port. Currently only supports TCP.
func FindProcessByPort(port int) (int, error) {
	if runtime.GOOS != "windows" {
		return 0, fmt.Errorf("only supported on windows")
	}

	// netstat -ano | findstr :PORT
	cmd := exec.Command("cmd", "/c", fmt.Sprintf("netstat -ano | findstr :%d", port))
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return 0, nil // not found usually means port is not occupied
	}

	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// TCP    0.0.0.0:8080           0.0.0.0:0              LISTENING       pid
		fields := strings.Fields(line)
		if len(fields) >= 5 && strings.Contains(fields[1], fmt.Sprintf(":%d", port)) {
			pid, err := strconv.Atoi(fields[len(fields)-1])
			if err == nil {
				return pid, nil
			}
		}
	}
	return 0, nil
}

// GetProcessNameByPID 获取指定 PID 的进程名。
func GetProcessNameByPID(pid int) (string, error) {
	if runtime.GOOS != "windows" {
		return "", fmt.Errorf("only supported on windows")
	}

	cmd := exec.Command("tasklist", "/FI", fmt.Sprintf("PID eq %d", pid), "/NH")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", err
	}

	// Image Name                     PID Session Name        Session#    Mem Usage
	// ========================= ======== ================ =========== ============
	// novaproxy.exe                13012 Console                    1     12,345 K
	line := strings.TrimSpace(string(out))
	if strings.Contains(line, "No tasks are running") {
		return "", fmt.Errorf("process not found")
	}
	fields := strings.Fields(line)
	if len(fields) > 0 {
		return fields[0], nil
	}
	return "", fmt.Errorf("failed to parse tasklist output")
}

// KillProcessByPID forcefully terminates the specified PID and its child processes.
func KillProcessByPID(pid int) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("only supported on windows")
	}
	cmd := exec.Command("taskkill", "/F", "/T", "/PID", fmt.Sprintf("%d", pid))
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.Run()
}

// EnsurePortAvailable checks port availability:
	// 1. If occupied by processes in selfNames list, try Kill.
	// 2. If occupied by other processes or Kill fails, find next available port.
func EnsurePortAvailable(startPort int, selfNames []string) (int, error) {
	currentPort := startPort
	maxAttempts := 10 // avoid infinite loop

	for i := 0; i < maxAttempts; i++ {
		pid, err := FindProcessByPort(currentPort)
		if err != nil || pid == 0 {
			// Port is idle, double-check actual availability
			ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", currentPort))
			if err == nil {
				ln.Close()
				return currentPort, nil
			}
			// net.Listen failed, still unavailable, skip to next
		} else {
			// Port occupied, check process name
			name, _ := GetProcessNameByPID(pid)
			isSelf := false
			for _, self := range selfNames {
				if strings.EqualFold(name, self) || strings.EqualFold(name, self+".exe") {
					isSelf = true
					break
				}
			}

			if isSelf {
				// 是己方进程，尝试 Kill
				if err := KillProcessByPID(pid); err == nil {
					// 给系统一点时间回收资源
					return currentPort, nil
				}
			}
		}

		// Conflict and cannot handle, try next port
		currentPort++
	}

	return startPort, fmt.Errorf("could not find available port after %d attempts", maxAttempts)
}
