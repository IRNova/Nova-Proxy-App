package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"novaproxy/proxy"
)

type externalMihomoManager struct {
	mu         sync.Mutex
	corePath   string
	runtimeDir string
	configPath string
	pidPath    string
	logBuffer  *ringLogWriter
}

func newExternalMihomoManager() *externalMihomoManager {
	root := resolveExternalMihomoRoot()
	return &externalMihomoManager{
		corePath:   filepath.Join(root, "core", "mihomo", "mihomo.exe"),
		runtimeDir: filepath.Join(root, "runtime", "mihomo"),
		configPath: filepath.Join(root, "runtime", "mihomo", "config.yaml"),
		pidPath:    filepath.Join(root, "runtime", "mihomo", "mihomo.pid"),
		logBuffer:  newRingLogWriter(50),
	}
}

func resolveExternalMihomoRoot() string {
	if execPath, err := os.Executable(); err == nil {
		if execDir := strings.TrimSpace(filepath.Dir(execPath)); execDir != "" {
			return execDir
		}
	}
	return "."
}

func (m *externalMihomoManager) Start(cfg proxy.TUNConfig, listenPort string, logf func(string)) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if runtime.GOOS != "windows" {
		return fmt.Errorf("external mihomo TUN is only supported on Windows")
	}
	listenPort = strings.TrimSpace(listenPort)
	if listenPort == "" {
		return fmt.Errorf("proxy listen port is empty")
	}
	if err := m.ensureConfigLocked(cfg, listenPort); err != nil {
		return err
	}
	if err := m.stopLocked(nil); err != nil {
		return err
	}

	cmd := exec.Command(m.corePath, "-d", m.runtimeDir, "-f", m.configPath)
	cmd.Dir = m.runtimeDir
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	m.logBuffer.Clear()
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		return err
	}

	go func() {
		if stdout != nil {
			buf := make([]byte, 1024)
			for {
				n, err := stdout.Read(buf)
				if n > 0 {
					_, _ = m.logBuffer.Write(buf[:n])
				}
				if err != nil {
					break
				}
			}
		}
	}()

	go func() {
		if stderr != nil {
			buf := make([]byte, 1024)
			for {
				n, err := stderr.Read(buf)
				if n > 0 {
					_, _ = m.logBuffer.Write(buf[:n])
				}
				if err != nil {
					break
				}
			}
		}
	}()
	_ = os.WriteFile(m.pidPath, []byte(strconv.Itoa(cmd.Process.Pid)), 0644)

	go func() {
		err := cmd.Wait()
		if logf != nil {
			if err != nil {
				logf(fmt.Sprintf("[mihomo] process exited: %v", err))
			} else {
				logf("[mihomo] process exited")
			}
		}
	}()

	deadline := time.Now().Add(12 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(300 * time.Millisecond)
		running, message := m.runningStateLocked(cfg)
		if running {
			if logf != nil {
				logf("[mihomo] external TUN started")
			}
			return nil
		}
		if isFatalMihomoMessage(message) {
			return fmt.Errorf(message)
		}
	}
	_, message := m.runningStateLocked(cfg)
	if strings.TrimSpace(message) != "" {
		return fmt.Errorf(message)
	}
	return fmt.Errorf("external mihomo TUN did not enter running state")
}

func (m *externalMihomoManager) Stop(logf func(string)) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.stopLocked(logf)
}

func (m *externalMihomoManager) stopLocked(logf func(string)) error {
	pid, _ := m.readPIDLocked()
	if pid == 0 {
		_ = os.Remove(m.pidPath)
		return nil
	}
	proc, err := os.FindProcess(pid)
	if err == nil && proc != nil {
		_ = proc.Kill()
	}
	_ = os.Remove(m.pidPath)
	if logf != nil {
		logf("[mihomo] external TUN stopped")
	}
	return nil
}

func (m *externalMihomoManager) RestartIfRunning(cfg proxy.TUNConfig, listenPort string, logf func(string)) error {
	m.mu.Lock()
	_, pid := m.statusMessageLocked(cfg)
	running := pid > 0
	m.mu.Unlock()
	if !running {
		return nil
	}
	if logf != nil {
		logf("[mihomo] reloading external TUN config")
	}
	return m.Start(cfg, listenPort, logf)
}

func (m *externalMihomoManager) Status(cfg proxy.TUNConfig) proxy.TUNStatus {
	m.mu.Lock()
	defer m.mu.Unlock()

	status := proxy.TUNStatus{
		Supported: runtime.GOOS == "windows",
		Enabled:   false,
		Running:   false,
		Stack:     strings.TrimSpace(cfg.Stack),
		Driver:    "mihomo",
		Message:   "External Mihomo TUN is configured but not running",
	}
	if status.Stack == "" {
		status.Stack = "gvisor"
	}
	if _, err := os.Stat(m.corePath); err != nil {
		status.Message = fmt.Sprintf("Mihomo core not found: %s", m.corePath)
		return status
	}
	running, message := m.runningStateLocked(cfg)
	status.Running = running
	status.Enabled = running
	if strings.TrimSpace(message) != "" {
		status.Message = message
	}
	return status
}

func (m *externalMihomoManager) ensureConfigLocked(cfg proxy.TUNConfig, listenPort string) error {
	listenPort = strings.TrimSpace(listenPort)
	if listenPort == "" {
		return fmt.Errorf("proxy listen port is empty")
	}
	if err := os.MkdirAll(m.runtimeDir, 0755); err != nil {
		return err
	}
	if _, err := os.Stat(m.corePath); err != nil {
		return fmt.Errorf("mihomo core not found: %s", m.corePath)
	}
	appProcess := "novaproxy.exe"
	if exePath, err := os.Executable(); err == nil {
		if name := strings.TrimSpace(filepath.Base(exePath)); name != "" {
			appProcess = name
		}
	}
	config := strings.ReplaceAll(mihomoConfigTemplate, "__NOVAPROXY_PORT__", listenPort)
	// همچنین برای سازگاری با قالب‌های قدیمی (اگر کسی از __NOVAPROXY_PORT_OLD__ استفاده می‌کند) هر دو را جایگزین کنید
	config = strings.ReplaceAll(config, "__NOVAPROXY_PORT_OLD__", listenPort)
	config = strings.ReplaceAll(config, "__APP_PROCESS__", appProcess)
	return os.WriteFile(m.configPath, []byte(config), 0644)
}

func (m *externalMihomoManager) runningStateLocked(cfg proxy.TUNConfig) (bool, string) {
	message, pid := m.statusMessageLocked(cfg)
	if pid == 0 {
		return false, message
	}
	lines := m.recentLogLinesLocked(200)
	for _, line := range lines {
		if isReadyMihomoLine(line) {
			return true, "External Mihomo TUN is running"
		}
	}
	return false, message
}

func (m *externalMihomoManager) statusMessageLocked(cfg proxy.TUNConfig) (string, int) {
	pid, _ := m.readPIDLocked()
	if pid == 0 {
		return "External Mihomo TUN is configured but not running", 0
	}
	if !processRunning(pid) {
		_ = os.Remove(m.pidPath)
		return "External Mihomo process is not running", 0
	}
	lines := m.recentLogLinesLocked(200)
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if fatal := fatalMihomoLine(line); fatal != "" {
			return fatal, pid
		}
		if isReadyMihomoLine(line) {
			return "External Mihomo TUN is running", pid
		}
	}
	return "External Mihomo process is starting", pid
}

func (m *externalMihomoManager) recentLogLinesLocked(limit int) []string {
	if m.logBuffer == nil {
		return []string{}
	}
	return m.logBuffer.Snapshot(limit)
}

func (m *externalMihomoManager) readPIDLocked() (int, error) {
	data, err := os.ReadFile(m.pidPath)
	if err != nil {
		return 0, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 0 {
		return 0, fmt.Errorf("invalid mihomo pid")
	}
	return pid, nil
}

func processRunning(pid int) bool {
	if pid <= 0 {
		return false
	}
	_, err := os.FindProcess(pid)
	return err == nil
}

func isFatalMihomoMessage(message string) bool {
	msg := strings.ToLower(strings.TrimSpace(message))
	if msg == "" {
		return false
	}
	return strings.Contains(msg, "start tun listening error:") ||
		strings.Contains(msg, "access is denied") ||
		strings.Contains(msg, "configure tun interface")
}

func fatalMihomoLine(line string) string {
	line = strings.TrimSpace(line)
	if line == "" {
		return ""
	}
	lower := strings.ToLower(line)
	switch {
	case strings.Contains(lower, "start tun listening error:"):
		if idx := strings.Index(lower, "start tun listening error:"); idx >= 0 {
			return strings.TrimSpace(line[idx:])
		}
		return line
	case strings.Contains(lower, "access is denied"),
		strings.Contains(lower, "configure tun interface"),
		strings.Contains(lower, "failed to start tun"):
		return line
	default:
		return ""
	}
}

func isReadyMihomoLine(line string) bool {
	lower := strings.ToLower(strings.TrimSpace(line))
	if lower == "" {
		return false
	}
	return strings.Contains(lower, "tun adapter listening at") ||
		strings.Contains(lower, "[tcp]") ||
		strings.Contains(lower, "[udp]") ||
		strings.Contains(lower, "match using proxy[") ||
		strings.Contains(lower, "start initial compatible provider")
}

const mihomoConfigTemplate = `mixed-port: 7890
allow-lan: false
mode: rule
log-level: info
ipv6: true
find-process-mode: always
unified-delay: false
tcp-concurrent: true

profile:
  store-selected: true
  store-fake-ip: true

proxies:
  - name: novaproxy-local
    type: http
    server: 127.0.0.1
    port: __NOVAPROXY_PORT__

proxy-groups:
  - name: PROXY
    type: select
    proxies:
      - novaproxy-local
      - DIRECT

rules:
  - PROCESS-NAME,__APP_PROCESS__,DIRECT
  - PROCESS-NAME,mihomo.exe,DIRECT
  - DOMAIN-SUFFIX,local,DIRECT
  - DOMAIN-SUFFIX,lan,DIRECT
  - IP-CIDR,127.0.0.0/8,DIRECT,no-resolve
  - IP-CIDR,10.0.0.0/8,DIRECT,no-resolve
  - IP-CIDR,100.64.0.0/10,DIRECT,no-resolve
  - IP-CIDR,172.16.0.0/12,DIRECT,no-resolve
  - IP-CIDR,192.168.0.0/16,DIRECT,no-resolve
  - IP-CIDR,198.18.0.0/16,DIRECT,no-resolve
  - IP-CIDR,224.0.0.0/4,DIRECT,no-resolve
  - IP-CIDR6,::1/128,DIRECT,no-resolve
  - IP-CIDR6,fc00::/7,DIRECT,no-resolve
  - IP-CIDR6,fe80::/10,DIRECT,no-resolve
  - MATCH,PROXY

tun:
  enable: true
  stack: gvisor
  auto-route: true
  auto-detect-interface: true
  dns-hijack:
    - any:53
    - tcp://any:53

dns:
  enable: true
  ipv6: true
  listen: 127.0.0.1:1053
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
`
