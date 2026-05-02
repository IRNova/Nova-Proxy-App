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

// FindProcessByPort returns the PID of the process listening on the given port (TCP only).
func FindProcessByPort(port int) (int, error) {
	if runtime.GOOS != "windows" {
		return 0, fmt.Errorf("only supported on windows")
	}

	// netstat -ano | findstr :PORT
	cmd := exec.Command("cmd", "/c", fmt.Sprintf("netstat -ano | findstr :%d", port))
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return 0, nil // not found likely means port not in use
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

// GetProcessNameByPID returns the name of the process with the given PID.
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

	// Example output:
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

// KillProcessByPID forcefully terminates the given PID and its child processes.
func KillProcessByPID(pid int) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("only supported on windows")
	}
	cmd := exec.Command("taskkill", "/F", "/T", "/PID", fmt.Sprintf("%d", pid))
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.Run()
}

// EnsurePortAvailable checks port occupation:
// 1. If occupied by a process in selfNames list, attempt to kill it.
// 2. If occupied by another process or killing fails, find the next free port.
func EnsurePortAvailable(startPort int, selfNames []string) (int, error) {
	currentPort := startPort
	maxAttempts := 10 // Avoid infinite loop

	for i := 0; i < maxAttempts; i++ {
		pid, err := FindProcessByPort(currentPort)
		if err != nil || pid == 0 {
			// Port seems free; double-check by binding
			ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", currentPort))
			if err == nil {
				ln.Close()
				return currentPort, nil
			}
			// If net.Listen fails, the port is still unusable; move on.
		} else {
			// Port is occupied; check process name
			name, _ := GetProcessNameByPID(pid)
			isSelf := false
			for _, self := range selfNames {
				if strings.EqualFold(name, self) || strings.EqualFold(name, self+".exe") {
					isSelf = true
					break
				}
			}

			if isSelf {
				// It's our own process; try to kill it
				if err := KillProcessByPID(pid); err == nil {
					// Give the system a moment to release resources
					return currentPort, nil
				}
			}
		}

		// Conflict and cannot handle; try next port
		currentPort++
	}

	return startPort, fmt.Errorf("could not find available port after %d attempts", maxAttempts)
}
