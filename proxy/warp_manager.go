package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

type WarpStatus struct {
	Running bool   `json:"running"`
	Account string `json:"account_id"`
	Mode    string `json:"mode"`
	Error   string `json:"error,omitempty"`
}

type WarpManager struct {
	BinPath     string
	ConfigDir   string
	SocksPort   int
	cmd         *exec.Cmd
	ctx         context.Context
	cancel      context.CancelFunc
	mu          sync.RWMutex
	running     bool
	lastError   error
	onLogUpdate func(string)
}

func NewWarpManager(execDir string) *WarpManager {
	binName := "usque.exe"
	if runtime.GOOS != "windows" {
		binName = "usque"
	}

	configDir := resolveRuntimeDir(execDir, "proxy", binName)

	return &WarpManager{
		BinPath:   filepath.Join(configDir, binName),
		ConfigDir: configDir,
		SocksPort: 1080,
	}
}

func resolveRuntimeDir(execDir, dirName, markerFile string) string {
	candidates := []string{
		filepath.Join(execDir, dirName),
		filepath.Join(execDir, "..", dirName),
		filepath.Join(execDir, "..", "..", dirName),
	}

	for _, candidate := range candidates {
		markerPath := filepath.Join(candidate, markerFile)
		if _, err := os.Stat(markerPath); err == nil {
			return candidate
		}
	}

	return filepath.Join(execDir, dirName)
}

func (m *WarpManager) SetEndpoint(endpoint string) error {
	if endpoint == "" {
		return nil
	}
	configPath := filepath.Join(m.ConfigDir, "config.json")
	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // Not yet registered, ignore
		}
		return err
	}

	var config map[string]interface{}
	if err := json.Unmarshal(data, &config); err != nil {
		return err
	}

	config["endpoint_v4"] = endpoint
	// endpoint_v6 is usually left as default or assigned by Cloudflare; not modified here.

	newData, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(configPath, newData, 0644)
}

func (m *WarpManager) SetLogCallback(cb func(string)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onLogUpdate = cb
}

func (m *WarpManager) appendLog(msg string) {
	m.mu.RLock()
	cb := m.onLogUpdate
	m.mu.RUnlock()
	if cb != nil {
		cb("[Warp] " + msg)
	}
	log.Printf("[Warp] %s", msg)
}

func (m *WarpManager) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.running {
		return nil
	}

	// Check if binary exists
	if _, err := os.Stat(m.BinPath); os.IsNotExist(err) {
		return fmt.Errorf("usque binary not found at %s", m.BinPath)
	}

	m.ctx, m.cancel = context.WithCancel(context.Background())
	ctx := m.ctx

	go m.runLoop(ctx)

	m.running = true
	return nil
}

func (m *WarpManager) Stop() error {
	m.mu.Lock()
	if !m.running {
		m.mu.Unlock()
		return nil
	}

	cancel := m.cancel
	cmd := m.cmd
	m.running = false
	m.cancel = nil
	m.ctx = nil
	m.cmd = nil
	m.mu.Unlock()

	if cancel != nil {
		cancel()
	}

	if cmd != nil && cmd.Process != nil {
		// On Windows, graceful exit may not work well; kill normally.
		_ = cmd.Process.Kill()

		// Extra forceful cleanup on Windows (if process didn't die)
		if runtime.GOOS == "windows" {
			killCmd := exec.Command("taskkill", "/F", "/T", "/PID", fmt.Sprintf("%d", cmd.Process.Pid))
			m.setupHiddenWindow(killCmd)
			_ = killCmd.Run()
		}
	}

	m.appendLog("Stopped")
	return nil
}

func (m *WarpManager) runLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			err := m.execute(ctx)
			if err != nil {
				m.mu.Lock()
				m.lastError = err
				m.mu.Unlock()
				m.appendLog(fmt.Sprintf("Process exited with error: %v", err))
			}
			
			// If context is not done, wait a bit and restart
			select {
			case <-ctx.Done():
				return
			case <-time.After(3 * time.Second):
				m.appendLog("Restarting usque...")
			}
		}
	}
}

func (m *WarpManager) execute(ctx context.Context) error {
	// 1. Port availability check and cleanup
	availablePort, err := EnsurePortAvailable(m.SocksPort, []string{"usque", "novaproxy"})
	if err == nil && availablePort != m.SocksPort {
		m.appendLog(fmt.Sprintf("SOCKS port %d occupied, switched to %d", m.SocksPort, availablePort))
		m.SocksPort = availablePort
	}

	args := []string{"socks", "-p", fmt.Sprintf("%d", m.SocksPort)}
	
	cmd := exec.CommandContext(ctx, m.BinPath, args...)
	cmd.Dir = m.ConfigDir
	m.setupHiddenWindow(cmd)

	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()

	m.mu.Lock()
	m.cmd = cmd
	m.lastError = nil
	m.mu.Unlock()

	m.appendLog(fmt.Sprintf("Starting usque socks on port %d...", m.SocksPort))
	
	if err := cmd.Start(); err != nil {
		return err
	}

	// Capture logs in real time
	go m.copyLog(stdout)
	go m.copyLog(stderr)

	err = cmd.Wait()
	if err != nil {
		return fmt.Errorf("exit: %v", err)
	}
	return nil
}

func (m *WarpManager) copyLog(r io.Reader) {
	buf := make([]byte, 1024)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			m.appendLog(string(buf[:n]))
		}
		if err != nil {
			break
		}
	}
}

func (m *WarpManager) IsReady() bool {
	addr := fmt.Sprintf("127.0.0.1:%d", m.SocksPort)
	conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func (m *WarpManager) Register(deviceName string) (string, error) {
	args := []string{"register"}
	if deviceName != "" {
		args = append(args, "-n", deviceName)
	}

	cmd := exec.Command(m.BinPath, args...)
	cmd.Dir = m.ConfigDir
	cmd.Stdin = strings.NewReader("y\n") // Auto-accept terms of use
	m.setupHiddenWindow(cmd)

	m.appendLog(fmt.Sprintf("Executing: %s register (at %s)", m.BinPath, m.ConfigDir))
	m.appendLog("Registering new Warp account... (Please wait, CF API might be slow)")
	
	out, err := cmd.CombinedOutput()
	if err != nil {
		m.appendLog(fmt.Sprintf("Register failed with error: %v, Output: %s", err, string(out)))
		return string(out), err
	}
	m.appendLog("Register success output: " + string(out))
	return string(out), nil
}

func (m *WarpManager) Enroll() (string, error) {
	cmd := exec.Command(m.BinPath, "enroll")
	cmd.Dir = m.ConfigDir
	cmd.Stdin = strings.NewReader("y\n") // Auto-accept terms of use (if needed)
	m.setupHiddenWindow(cmd)

	m.appendLog(fmt.Sprintf("Executing: %s enroll (at %s)", m.BinPath, m.ConfigDir))
	m.appendLog("Enrolling existing Warp key...")
	
	out, err := cmd.CombinedOutput()
	if err != nil {
		m.appendLog(fmt.Sprintf("Enroll failed with error: %v, Output: %s", err, string(out)))
		return string(out), err
	}
	m.appendLog("Enroll success output: " + string(out))
	return string(out), nil
}

func (m *WarpManager) GetStatus() WarpStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()

	status := WarpStatus{
		Running: m.running,
		Mode:    "MASQUE",
	}

	if m.lastError != nil {
		status.Error = m.lastError.Error()
	}

	// Try to read account ID from config.json
	configPath := filepath.Join(m.ConfigDir, "config.json")
	if data, err := os.ReadFile(configPath); err == nil {
		var cfg struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(data, &cfg); err == nil {
			status.Account = cfg.ID
		} else {
			m.appendLog(fmt.Sprintf("[debug] Failed to unmarshal warp config: %v", err))
		}
	} else {
		// Only log debug info when running and not "not exist" to avoid noise
		if m.running && !os.IsNotExist(err) {
			m.appendLog(fmt.Sprintf("[debug] Failed to read warp config at %s: %v", configPath, err))
		}
		// Log the path if file missing (for diagnostics)
		if os.IsNotExist(err) && m.running {
			m.appendLog(fmt.Sprintf("[diag] Warp config.json NOT found at expected path: %s", configPath))
		}
	}

	return status
}
