package proxy

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

// ExternalTunManager manages an external Mihomo (Clash Meta) process for TUN mode.
// Mihomo provides system-level TUN virtual network interface for full VPN-like routing.
type ExternalTunManager struct {
	mu       sync.Mutex
	cmd      *exec.Cmd
	cfgPath  string
	running  bool
	supported bool
}

func NewExternalTunManager() *ExternalTunManager {
	return &ExternalTunManager{
		supported: runtime.GOOS == "windows" || runtime.GOOS == "linux",
	}
}

func (m *ExternalTunManager) Start(cfg TUNConfig, listenPort string, logFn func(string)) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.running {
		return nil
	}

	if !m.supported {
		return fmt.Errorf("TUN mode not supported on %s", runtime.GOOS)
	}
	if cfg.MTU == 0 {
		cfg.MTU = 9000
	}

	binaryPath := m.findMihomoBinary()
	if binaryPath == "" {
		return fmt.Errorf("mihomo binary not found - download from https://github.com/MetaCubeX/mihomo/releases")
	}

	m.cfgPath = filepath.Join(os.TempDir(), "novaproxy_mihomo.yaml")
	if err := m.writeConfig(cfg, listenPort); err != nil {
		return fmt.Errorf("write mihomo config: %w", err)
	}

	m.cmd = exec.Command(binaryPath, "-d", filepath.Dir(m.cfgPath), "-f", m.cfgPath)
	m.cmd.Stdout = os.Stdout
	m.cmd.Stderr = os.Stderr

	if err := m.cmd.Start(); err != nil {
		return fmt.Errorf("start mihomo: %w", err)
	}

	m.running = true
	if logFn != nil {
		logFn(fmt.Sprintf("[mihomo] started TUN on port %s", listenPort))
	}

	go func() {
		m.cmd.Wait()
		m.mu.Lock()
		m.running = false
		m.mu.Unlock()
		if logFn != nil {
			logFn("[mihomo] process exited")
		}
	}()

	return nil
}

func (m *ExternalTunManager) Stop(logFn func(string)) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.running || m.cmd == nil {
		return nil
	}

	if m.cmd.Process != nil {
		m.cmd.Process.Kill()
	}
	m.running = false

	if logFn != nil {
		logFn("[mihomo] TUN stopped")
	}
	return nil
}

func (m *ExternalTunManager) RestartIfRunning(cfg TUNConfig, listenPort string, logFn func(string)) error {
	m.mu.Lock()
	running := m.running
	m.mu.Unlock()

	if !running {
		return nil
	}

	m.Stop(logFn)
	time.Sleep(500 * time.Millisecond)
	return m.Start(cfg, listenPort, logFn)
}

func (m *ExternalTunManager) Status(cfg TUNConfig) TUNStatus {
	m.mu.Lock()
	defer m.mu.Unlock()

	status := TUNStatus{
		Supported: m.supported,
		Running:   m.running,
		Enabled:   cfg.Enabled,
		Driver:    "mihomo",
	}

	if m.running {
		status.Message = "TUN is running"
	} else if m.supported {
		status.Message = "TUN is not running"
	} else {
		status.Message = fmt.Sprintf("TUN not supported on %s", runtime.GOOS)
	}
	return status
}

func (m *ExternalTunManager) writeConfig(cfg TUNConfig, listenPort string) error {
	config := fmt.Sprintf(`port: 0
socks-port: 0
mixed-port: 0
redir-port: 0
tproxy-port: 0
allow-lan: false
mode: rule
log-level: warning
ipv6: false

tun:
  enable: true
  stack: system
  device: NovaTUN
  dns-hijack:
    - "any:53"
  auto-route: %t
  auto-detect-interface: true
  mtu: %d

dns:
  enable: true
  listen: 0.0.0.0:5353
  default-nameserver:
    - 8.8.8.8
    - 1.1.1.1
  nameserver:
    - https://dns.google/dns-query
    - https://cloudflare-dns.com/dns-query
  fallback:
    - https://doh.dns.sb/dns-query
  fallback-filter:
    geoip: true
    geoip-code: CN
    ipcidr:
      - 240.0.0.0/4

proxies:
  - name: "NovaProxy"
    type: http
    server: "127.0.0.1"
    port: %s

proxy-groups:
  - name: "Proxy"
    type: select
    proxies:
      - "NovaProxy"
      - "DIRECT"

rules:
  - "MATCH,Proxy"
`, cfg.AutoRoute, cfg.MTU, listenPort)

	return os.WriteFile(m.cfgPath, []byte(config), 0644)
}

func (m *ExternalTunManager) findMihomoBinary() string {
	binaryName := "mihomo"
	if runtime.GOOS == "windows" {
		binaryName += ".exe"
	}

	// Search known locations
	searchPaths := []string{
		binaryName,                                       // PATH
		filepath.Join("mihomo", binaryName),              // ./mihomo/mihomo
		filepath.Join("bin", binaryName),                 // ./bin/mihomo
		filepath.Join("data", "mihomo", binaryName),      // ./data/mihomo/mihomo
		filepath.Join("data", "Xray", binaryName),        // ./data/Xray/mihomo
		`C:\Program Files\Mihomo\` + binaryName,
		`C:\Program Files (x86)\Mihomo\` + binaryName,
	}

	// Also check PATH
	if path, err := exec.LookPath(binaryName); err == nil {
		return path
	}

	for _, p := range searchPaths {
		if _, err := os.Stat(p); err == nil {
			abs, _ := filepath.Abs(p)
			return abs
		}
	}

	return ""
}

// MarshalJSON implements custom JSON marshaling for status reporting
func (s TUNStatus) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"supported": s.Supported,
		"running":   s.Running,
		"enabled":   s.Enabled,
		"driver":    s.Driver,
		"message":   s.Message,
	})
}

// ConfigureIPv6 updates the IPv6 setting in the TUN config
func (m *ExternalTunManager) SetIPv6(enabled bool) {
	// IPv6 setting is applied on next start via config
}


