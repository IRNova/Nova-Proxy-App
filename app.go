package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"time"
	"unsafe"

	"novaproxy/cert"
	"novaproxy/proxy"
	"novaproxy/sysproxy"

	"github.com/wailsapp/wails/v3/pkg/application"
	"golang.org/x/sys/windows"
)

type App struct {
	wailsApp          *application.App
	mainWindow        *application.WebviewWindow
	proxyServer       *proxy.ProxyServer
	certManager       *cert.CertManager
	ruleManager       *proxy.RuleManager
	certPath          string
	proxyMarkerPath   string
	logBuffer         *ringLogWriter
	logCaptureMu      sync.RWMutex
	logCaptureEnabled bool
	shouldQuit        bool
	systemTray        *application.SystemTray
	trayMenuV3        *application.Menu
	proxyItemV3       *application.MenuItem
	systemProxyItemV3 *application.MenuItem
	proxyOpMu         sync.Mutex
	systemProxyOpMu   sync.Mutex
	launchedAtStartup bool
	core              *coreClient
	gsaManager        *proxy.GSAManager

	// Real CPU usage tracking (Windows)
	cpuMu          sync.Mutex
	prevCPUIdle    uint64
	prevCPUKernel  uint64
	prevCPUUser    uint64
	firstCPUCall   bool

	// Track stats for traffic speed calculations
	lastIn   int64
	lastOut  int64
	lastTick time.Time

	trafficStopCh chan struct{}
}

type ringLogWriter struct {
	mu      sync.Mutex
	lines   []string
	pending string
	max     int
}

type gatedLogWriter struct {
	app *App
}

type managedSystemProxyMarker struct {
	Server string `json:"server"`
}

func newRingLogWriter(max int) *ringLogWriter {
	if max <= 0 {
		max = 1000
	}
	return &ringLogWriter{
		lines: make([]string, 0, max),
		max:   max,
	}
}

func (w *ringLogWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	text := w.pending + strings.ReplaceAll(string(p), "\r\n", "\n")
	parts := strings.Split(text, "\n")
	if len(parts) == 0 {
		return len(p), nil
	}
	w.pending = parts[len(parts)-1]
	for _, line := range parts[:len(parts)-1] {
		if line == "" {
			continue
		}
		w.lines = append(w.lines, line)
		if len(w.lines) > w.max {
			// Slicing keeps the underlying array.
			// To truly assist GC and shrink cap, we re-allocate if it grows 2x over max.
			if cap(w.lines) > w.max*2 {
				newLines := make([]string, w.max)
				copy(newLines, w.lines[len(w.lines)-w.max:])
				w.lines = newLines
			} else {
				w.lines = w.lines[len(w.lines)-w.max:]
			}
		}
	}
	return len(p), nil
}

func (w *ringLogWriter) Snapshot(limit int) []string {
	if limit <= 0 {
		limit = 200
	}
	w.mu.Lock()
	defer w.mu.Unlock()

	total := len(w.lines)
	if total == 0 {
		if w.pending != "" {
			return []string{w.pending}
		}
		return []string{}
	}
	if limit > total {
		limit = total
	}
	start := total - limit
	out := make([]string, limit)
	copy(out, w.lines[start:])

	// If we have pending text and space in out, or just append it if we want latest
	if w.pending != "" {
		out = append(out, w.pending)
		if len(out) > limit {
			out = out[1:]
		}
	}
	return out
}

func (w *ringLogWriter) Clear() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.lines = w.lines[:0]
	w.pending = ""
}

func (w *ringLogWriter) AppendLine(line string) {
	if line == "" {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.lines = append(w.lines, line)
	if len(w.lines) > w.max {
		w.lines = w.lines[len(w.lines)-w.max:]
	}
}

func (w *gatedLogWriter) Write(p []byte) (int, error) {
	if w == nil || w.app == nil || !w.app.IsLogCaptureEnabled() {
		return len(p), nil
	}
	if w.app.logBuffer == nil {
		w.app.logBuffer = newRingLogWriter(5000)
	}
	_, err := w.app.logBuffer.Write(p)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func NewApp() *App {
	execPath, _ := os.Executable()
	execDir := filepath.Dir(execPath)
	settingsPath := resolveRuntimeFile(execDir, filepath.Join("data", "config", "settings.json"))
	rulesPath := resolveRuntimeFile(execDir, filepath.Join("data", "rules", "config.json"))

	ruleManager := proxy.NewRuleManager(settingsPath, rulesPath)
	if err := ruleManager.LoadConfig(); err != nil {
		log.Printf("[warn] Failed to load config at init: %v", err)
	}

	host := ruleManager.GetListenHost()
	if host == "" {
		host = "127.0.0.1"
	}
	port := ruleManager.GetListenPort()
	if port == "" {
		port = "8080"
	}

	a := &App{
		proxyServer:       proxy.NewProxyServer(host + ":" + port),
		ruleManager:       ruleManager,
		certPath:          filepath.Join(execDir, "data", "cert"),
		proxyMarkerPath:   filepath.Join(execDir, "data", "config", "system_proxy_owner.json"),
		launchedAtStartup: hasLaunchArg("--startup"),
		core:              newCoreClient(),
	}

	// Read SOCKS5 address from persistent config
	if err := a.proxyServer.SetSOCKSAddr(ruleManager.GetSocksAddr()); err != nil {
		log.Printf("[warn] Failed to set SOCKS5 address: %v", err)
	}

	// Initialize GSA (Cloudflare Warp / Domain Fronting) manager
	a.gsaManager = proxy.NewGSAManager(filepath.Join(execDir, "data"))
	if err := a.gsaManager.LoadConfig(); err != nil {
		log.Printf("[warn] Failed to load GSA config: %v", err)
	}

	// Initialize Cloudflare IP pool and trigger background health check on startup
	cf := ruleManager.GetCloudflareConfig()
	if len(cf.PreferredIPs) > 0 {
		a.proxyServer.UpdateCloudflareIPPool(cf.PreferredIPs)
		go func() {
			time.Sleep(1 * time.Second) // Wait for app to stabilize
			a.proxyServer.TriggerCFHealthCheck()
		}()
	}

	// Periodic auto-update task (every 24h)
	go func() {
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			config := a.ruleManager.GetCloudflareConfig()
			if config.AutoUpdate {
				log.Printf("[Cloudflare] Running scheduled auto-update")
				a.RefreshCloudflareIPPool()
			}
		}
	}()

	return a
}

func resolveRuntimeFile(execDir, relativePath string) string {
	return filepath.Join(execDir, relativePath)
}

func hasLaunchArg(flag string) bool {
	for _, arg := range os.Args[1:] {
		if strings.EqualFold(strings.TrimSpace(arg), flag) {
			return true
		}
	}
	return false
}

func (a *App) isManagedSystemProxy(status SystemProxyStatus) bool {
	if !status.Enabled {
		return false
	}
	marker, err := a.loadManagedSystemProxyMarker()
	if err != nil || marker == nil {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(status.Server), strings.TrimSpace(marker.Server))
}

func (a *App) loadManagedSystemProxyMarker() (*managedSystemProxyMarker, error) {
	data, err := os.ReadFile(a.proxyMarkerPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var marker managedSystemProxyMarker
	if err := json.Unmarshal(data, &marker); err != nil {
		return nil, err
	}
	marker.Server = strings.TrimSpace(marker.Server)
	if marker.Server == "" {
		return nil, nil
	}
	return &marker, nil
}

func (a *App) saveManagedSystemProxyMarker(server string) error {
	server = strings.TrimSpace(server)
	if server == "" {
		return fmt.Errorf("managed system proxy marker server is empty")
	}

	dir := filepath.Dir(a.proxyMarkerPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	data, err := json.Marshal(managedSystemProxyMarker{Server: server})
	if err != nil {
		return err
	}

	return os.WriteFile(a.proxyMarkerPath, data, 0644)
}

func (a *App) clearManagedSystemProxyMarker() error {
	err := os.Remove(a.proxyMarkerPath)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func (a *App) ServiceStartup(ctx context.Context, options application.ServiceOptions) error {
	a.startupV3()
	return nil
}

func (a *App) ServiceShutdown() error {
	a.shutdown()
	return nil
}

func (a *App) startupV3() {
	a.setupFileLogger()
	log.Printf("[startup] NovaProxy startup hook entered")
	a.appendLog("[startup] in-memory log channel ready")

	execPath, _ := os.Executable()
	execDir := filepath.Dir(execPath)
	fallbackCADir := filepath.Join(execDir, "mhr-gsa-go-master", "ca")

	var err error
	a.certManager, err = cert.InitCertManagerWithFallback(a.certPath, fallbackCADir)
	if err != nil {
		a.appendLog("[startup] Failed to init cert manager: " + err.Error())
	} else {
		a.appendLog("[startup] Cert manager initialized: " + a.certPath)
	}

	// Config already loaded in NewApp(); no need to reload
	if err := a.syncAutoStartRegistration(); err != nil {
		a.appendLog("[startup] Failed to sync auto-start registration: " + err.Error())
	}

	a.proxyServer.SetRuleManager(a.ruleManager)
	a.proxyServer.UpdateCloudflareConfig(a.ruleManager.GetCloudflareConfig())
	a.proxyServer.SetCertGenerator(a.certManager)
	a.gsaManager.SetCertGenerator(a.certManager)
	a.proxyServer.SetLogCallback(a.appendLog)

	// Initialize AutoRouter for automatic routing
	a.ruleManager.InitAutoRouter(a.proxyServer.GetDoHResolver())
	a.ruleManager.SetOnConfigSaved(func() {
		if a.core != nil {
			a.core.reloadIfRunning()
		}
	})
	a.ruleManager.SetRouteEventCallback(func(domain, mode string) {
		application.InvokeAsync(func() {
			if a.mainWindow != nil {
				a.mainWindow.EmitEvent("app:route", map[string]string{
					"domain": domain,
					"mode":   mode,
				})
			}
		})
	})

	startupProxyStatus := a.GetSystemProxyStatus()
	managedProxyRecovered := a.isManagedSystemProxy(startupProxyStatus)
	if managedProxyRecovered {
		sysproxy.SetOriginalProxySettings(sysproxy.SystemProxyStatus{})
		a.appendLog("[startup] Detected leftover managed system proxy state; will recover proxy core and restore to disabled on exit")
	} else if err := sysproxy.SaveOriginalProxySettings(); err != nil {
		a.appendLog("[startup] Failed to save original proxy settings: " + err.Error())
	}
	if !managedProxyRecovered {
		if marker, err := a.loadManagedSystemProxyMarker(); err != nil {
			a.appendLog("[startup] Failed to read managed system proxy marker: " + err.Error())
		} else if marker != nil && !strings.EqualFold(strings.TrimSpace(startupProxyStatus.Server), marker.Server) {
			if err := a.clearManagedSystemProxyMarker(); err != nil {
				a.appendLog("[startup] Failed to clear stale managed system proxy marker: " + err.Error())
			}
		} else if !startupProxyStatus.Enabled && marker != nil {
			if err := a.clearManagedSystemProxyMarker(); err != nil {
				a.appendLog("[startup] Failed to clear disabled managed system proxy marker: " + err.Error())
			}
		}
	}

	a.appendLog("[startup] NovaProxy started successfully")
	a.emitNotification("info", "NovaProxy", "Application started successfully")

	// Keep startup passive: proxy is started manually by the user.
	go func() {
		a.UpdateTrayMenu()

		if a.ShouldAutoEnableProxyOnAutoStart() {
			a.appendLog("[startup] Auto-start launch detected, enabling proxy and system proxy...")
			if err := a.EnableSystemProxy(); err != nil {
				a.appendLog("[startup] Failed to auto-enable proxy on startup: " + err.Error())
			}
		} else if managedProxyRecovered && !a.IsProxyRunning() {
			a.appendLog("[startup] Recovering proxy core because system proxy is already pointing to NovaProxy...")
			if err := a.StartProxy(); err != nil {
				a.appendLog("[startup] Failed to recover proxy core: " + err.Error())
			}
		}

		// If auto update is enabled, fetch IPs immediately
		cfg := a.ruleManager.GetCloudflareConfig()
		if cfg.AutoUpdate {
			a.appendLog("[Cloudflare] Auto update is enabled, fetching initial IPs...")
			go a.RefreshCloudflareIPPool()
		}
		a.emitFrontendState()

		// Start traffic stats pusher (Clash style)
		trafficStop := make(chan struct{})
		a.trafficStopCh = trafficStop
		go func() {
			time.Sleep(500 * time.Millisecond) // Give the window time to settle

			a.lastIn, a.lastOut, _ = a.GetStats()
			a.lastTick = time.Now()

			ticker := time.NewTicker(1 * time.Second)
			defer ticker.Stop()

			for {
				select {
				case <-trafficStop:
					return
				case <-ticker.C:
				}

				if a.mainWindow == nil {
					continue
				}

				currentIn, currentOut, _ := a.GetStats()
				now := time.Now()
				duration := now.Sub(a.lastTick).Seconds()

				if duration > 0 {
					downSpeed := float64(currentIn-a.lastIn) / duration
					upSpeed := float64(currentOut-a.lastOut) / duration

					// Avoid negative values if stats reset
					if downSpeed < 0 {
						downSpeed = 0
					}
					if upSpeed < 0 {
						upSpeed = 0
					}

					var routeEvents []RouteEvent
					if a.core != nil {
						routeEvents = a.core.GetRouteEvents()
					}

					// Use InvokeAsync to ensure UI thread safety in Wails v3
					application.InvokeAsync(func() {
						if a.mainWindow != nil {
							a.mainWindow.EmitEvent("app:traffic", map[string]float64{
								"down": downSpeed,
								"up":   upSpeed,
							})

							for _, ev := range routeEvents {
								a.mainWindow.EmitEvent("app:route", map[string]string{
									"domain": ev.Domain,
									"mode":   ev.Mode,
								})
							}
						}
					})
				}

				a.lastIn = currentIn
				a.lastOut = currentOut
				a.lastTick = now
			}
		}()
	}()

}

func (a *App) beforeClose() bool {
	if !a.shouldQuit && a.GetCloseToTray() {
		a.mainWindow.Hide()
		return true // Cancel the close event
	}
	return false // Allow the close event
}

// SetTrayMenu is no longer needed in v3 as it's setup in main.go

func (a *App) QuitApp() {
	a.shouldQuit = true
	a.wailsApp.Quit()
}

func (a *App) RevealMainWindow() {
	if a.mainWindow == nil {
		return
	}
	a.mainWindow.Restore()
	a.mainWindow.Show()
	a.mainWindow.Focus()
}

func (a *App) HandleWindowClose() {
	if a.GetCloseToTray() && !a.shouldQuit && a.mainWindow != nil {
		a.mainWindow.Hide()
		return
	}
	a.QuitApp()
}

func (a *App) GetCloseToTray() bool {
	if a.ruleManager == nil {
		return false
	}
	return a.ruleManager.GetCloseToTray()
}

func (a *App) SetCloseToTray(enabled bool) error {
	if a.ruleManager == nil {
		return fmt.Errorf("RuleManager not initialized")
	}
	return a.ruleManager.SetCloseToTray(enabled)
}

func (a *App) GetAutoStart() bool {
	if a.ruleManager == nil {
		return false
	}
	return a.ruleManager.GetAutoStart()
}

func (a *App) SetAutoStart(enabled bool) error {
	if a.ruleManager == nil {
		return fmt.Errorf("RuleManager not initialized")
	}
	command := a.autoStartCommand()
	if enabled && command == "" {
		return fmt.Errorf("failed to resolve executable path")
	}
	if err := setAutoStartEnabled(enabled, command); err != nil {
		return err
	}
	return a.ruleManager.SetAutoStart(enabled)
}

func (a *App) GetShowMainWindowOnAutoStart() bool {
	if a.ruleManager == nil {
		return true
	}
	return a.ruleManager.GetShowMainWindowOnAutoStart()
}

func (a *App) SetShowMainWindowOnAutoStart(enabled bool) error {
	if a.ruleManager == nil {
		return fmt.Errorf("RuleManager not initialized")
	}
	return a.ruleManager.SetShowMainWindowOnAutoStart(enabled)
}

func (a *App) GetAutoEnableProxyOnAutoStart() bool {
	if a.ruleManager == nil {
		return false
	}
	return a.ruleManager.GetAutoEnableProxyOnAutoStart()
}

func (a *App) SetAutoEnableProxyOnAutoStart(enabled bool) error {
	if a.ruleManager == nil {
		return fmt.Errorf("RuleManager not initialized")
	}
	return a.ruleManager.SetAutoEnableProxyOnAutoStart(enabled)
}

func (a *App) GetLanguage() string {
	if a.ruleManager == nil {
		return ""
	}
	return a.ruleManager.GetLanguage()
}

func (a *App) SetLanguage(lang string) error {
	if a.ruleManager == nil {
		return fmt.Errorf("RuleManager not initialized")
	}
	return a.ruleManager.SetLanguage(lang)
}

func (a *App) GetTheme() string {
	if a.ruleManager == nil {
		return "dark"
	}
	return a.ruleManager.GetTheme()
}

func (a *App) SetTheme(theme string) error {
	if a.ruleManager == nil {
		return fmt.Errorf("RuleManager not initialized")
	}
	return a.ruleManager.SetTheme(theme)
}

func (a *App) GetCountry() string {
	if a.ruleManager == nil {
		return "iran"
	}
	return a.ruleManager.GetCountry()
}

func (a *App) SetCountry(country string) error {
	if a.ruleManager == nil {
		return fmt.Errorf("RuleManager not initialized")
	}
	return a.ruleManager.SetCountry(country)
}

func (a *App) ShouldStartHidden() bool {
	return a.launchedAtStartup && !a.GetShowMainWindowOnAutoStart()
}

func (a *App) ShouldAutoEnableProxyOnAutoStart() bool {
	return a.launchedAtStartup && a.GetAutoEnableProxyOnAutoStart()
}

func (a *App) syncAutoStartRegistration() error {
	if !a.GetAutoStart() {
		return setAutoStartEnabled(false, "")
	}
	command := a.autoStartCommand()
	if command == "" {
		return fmt.Errorf("failed to resolve executable path")
	}
	return setAutoStartEnabled(true, command)
}

func (a *App) autoStartCommand() string {
	execPath, err := os.Executable()
	if err != nil {
		return ""
	}
	return buildAutoStartCommand(execPath)
}

func (a *App) UpdateTrayMenu() {
	proxyRunning := a.IsProxyRunning()
	systemProxyEnabled := a.GetSystemProxyStatus().Enabled

	application.InvokeAsync(func() {
		if a.proxyItemV3 != nil {
			a.proxyItemV3.SetChecked(proxyRunning)
			if proxyRunning {
				a.proxyItemV3.SetLabel("Proxy: On")
			} else {
				a.proxyItemV3.SetLabel("Proxy: Off")
			}
		}
		if a.systemProxyItemV3 != nil {
			if systemProxyEnabled {
				a.systemProxyItemV3.SetLabel("System Proxy: On")
			} else {
				a.systemProxyItemV3.SetLabel("System Proxy: Off")
			}
		}
	})
}

func (a *App) refreshTrayMenuLater(delays ...time.Duration) {
	for _, delay := range delays {
		go func(delay time.Duration) {
			if delay > 0 {
				time.Sleep(delay)
			}
			a.UpdateTrayMenu()
		}(delay)
	}
}

func (a *App) runSafeAsync(name string, fn func()) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				a.appendLog(fmt.Sprintf("[panic] %s: %v\n%s", name, r, string(debug.Stack())))
			}
		}()
		fn()
	}()
}

func (a *App) emitNotification(nType, title, message string) {
	if a.mainWindow == nil {
		return
	}
	application.InvokeAsync(func() {
		a.mainWindow.EmitEvent("app:notification", map[string]string{
			"type":    nType,
			"title":   title,
			"message": message,
		})
	})
}

func (a *App) emitFrontendState() {
	if a.mainWindow == nil {
		return
	}

	gsaCfg := a.gsaManager.GetStatus()
	state := map[string]any{
		"proxyRunning":       a.IsProxyRunning(),
		"systemProxyEnabled": a.GetSystemProxyStatus().Enabled,
		"tunRunning":         a.GetTUNStatus().Running,
		"gsaRunning":         gsaCfg.Running,
		"gsaRequestCount":    gsaCfg.RequestCount,
		"gsaBandwidthBytes":  gsaCfg.BandwidthBytes,
		"gsaLatency":         gsaCfg.ConnectionLatency,
		"gsaGoogleIP":        gsaCfg.LastGoogleIP,
	}

	application.InvokeAsync(func() {
		a.mainWindow.EmitEvent("app:state", state)
	})
}

// --- GSA (Cloudflare Warp / Domain Fronting) API ---

func (a *App) GetGSAConfig() proxy.GSAConfig {
	return a.gsaManager.GetConfig()
}

func (a *App) UpdateGSAConfig(cfg proxy.GSAConfig) error {
	a.appendLog(fmt.Sprintf("[GSA] UpdateGSAConfig: wasRunning=%v new_auth_key_set=%v new_script_id_set=%v",
		a.gsaManager.IsRunning(),
		cfg.AuthKey != "" && cfg.AuthKey != "changeme",
		cfg.ScriptID != "" && cfg.ScriptID != "changeme"))
	wasRunning := a.gsaManager.IsRunning()
	if wasRunning {
		a.appendLog("[GSA] UpdateGSAConfig: stopping running GSA proxy")
		a.setGSADialAddr("")
		if err := a.gsaManager.Stop(); err != nil {
			a.appendLog(fmt.Sprintf("[warn] GSA stop during config update failed: %v", err))
		} else {
			a.appendLog("[GSA] UpdateGSAConfig: stop succeeded")
		}
	}
	err := a.gsaManager.UpdateConfig(cfg)
	if err != nil {
		a.appendLog(fmt.Sprintf("[GSA] UpdateGSAConfig: UpdateConfig failed: %v", err))
		return err
	}
	a.appendLog("[GSA] UpdateGSAConfig: config saved to disk")
	if wasRunning {
		a.appendLog("[GSA] UpdateGSAConfig: restarting GSA proxy")
		if err := a.gsaManager.Start(); err != nil {
			a.appendLog(fmt.Sprintf("[warn] GSA restart after config update failed: %v", err))
			return err
		}
		newCfg := a.gsaManager.GetConfig()
		a.appendLog(fmt.Sprintf("[GSA] UpdateGSAConfig: restart succeeded, running=%v", newCfg.Running))
		a.setGSADialAddr(fmt.Sprintf("127.0.0.1:%d", newCfg.ListenPort))
		a.appendLog("[GSA] UpdateGSAConfig: dial addr set")
	}
	return err
}

func (a *App) StartGSAProxy() error {
	a.appendLog("[GSA] StartGSAProxy called")
	cfgBefore := a.gsaManager.GetConfig()
	a.appendLog(fmt.Sprintf("[GSA] Before start: auth_key_set=%v script_id_set=%v running=%v proxy_running=%v",
		cfgBefore.AuthKey != "" && cfgBefore.AuthKey != "changeme",
		cfgBefore.ScriptID != "" && cfgBefore.ScriptID != "changeme",
		cfgBefore.Running,
		a.IsProxyRunning()))

	err := a.gsaManager.Start()
	if err != nil {
		a.appendLog(fmt.Sprintf("[GSA] Start failed: %v", err))
		a.emitNotification("error", "GSA", "Failed to start GSA: "+err.Error())
		return err
	}
	a.appendLog("[GSA] gsaManager.Start() returned nil — GSA proxy is running")

	cfg := a.gsaManager.GetConfig()
	addr := fmt.Sprintf("127.0.0.1:%d", cfg.ListenPort)
	a.appendLog(fmt.Sprintf("[GSA] Setting GSA dial address to: %s", addr))
	a.setGSADialAddr(addr)
	a.appendLog(fmt.Sprintf("[GSA] Start succeeded, dial address set to: %s", addr))
	a.emitNotification("info", "GSA", "GSA proxy started on port "+fmt.Sprintf("%d", cfg.ListenPort))
	return nil
}

func (a *App) StopGSAProxy() error {
	a.appendLog("[GSA] StopGSAProxy called")
	a.setGSADialAddr("")
	err := a.gsaManager.Stop()
	if err != nil {
		a.appendLog(fmt.Sprintf("[GSA] Stop failed: %v", err))
	} else {
		a.appendLog("[GSA] Stop succeeded")
	}
	return err
}

// setGSADialAddr sets the GSA dial address on both the local proxy and
// the core subprocess proxy (if running). This ensures traffic is correctly
// forwarded to the GSA proxy regardless of which proxy handles the request.
func (a *App) setGSADialAddr(addr string) {
	display := addr
	if display == "" {
		display = "(empty — clearing)"
	}
	a.proxyServer.SetGSADialAddr(addr)
	if a.core != nil && a.core.Ping() {
		a.appendLog(fmt.Sprintf("[GSA] setGSADialAddr: core reachable via RPC, setting addr=%s on core proxy", display))
		if err := a.core.SetGSADialAddr(addr); err != nil {
			a.appendLog(fmt.Sprintf("[warn] setGSADialAddr: core RPC failed: %v", err))
		} else {
			a.appendLog(fmt.Sprintf("[GSA] setGSADialAddr: core proxy updated to addr=%s", display))
		}
	} else {
		a.appendLog(fmt.Sprintf("[GSA] setGSADialAddr: core not reachable, setting addr=%s on local proxy only", display))
	}
}

func (a *App) GetGSAStatus() proxy.GSAConfig {
	return a.gsaManager.GetStatus()
}

func (a *App) ScanGoogleIPs() []proxy.GoogleIPResult {
	return a.gsaManager.ScanGoogleIPs()
}

func (a *App) TestGSAConnection() (int64, error) {
	return a.gsaManager.TestConnection()
}

func (a *App) TestGSARelay(cfg proxy.GSAConfig) proxy.GSATestResult {
	return a.gsaManager.TestRelay(cfg)
}

func (a *App) RunGSASpeedTest() proxy.SpeedTestResult {
	return a.gsaManager.RunSpeedTest()
}

func (a *App) GetGSAProxyApps() []string {
	return a.gsaManager.GetProxyApps()
}

func (a *App) SetGSAProxyApps(apps []string) {
	a.gsaManager.SetProxyApps(apps)
}

// HardwareStats represents real-time system resource usage.
type HardwareStats struct {
	CPUPercent    float64 `json:"cpu_percent"`
	RAMMB         float64 `json:"ram_mb"`
	RAMTotalMB    float64 `json:"ram_total_mb"`
	RAMPercent    float64 `json:"ram_percent"`
	Goroutines    int     `json:"goroutines"`
}

// GetHardwareStats returns real system resource usage.
func (a *App) GetHardwareStats() HardwareStats {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	ramMB := float64(m.Alloc) / 1024 / 1024
	goroutines := runtime.NumGoroutine()
	sysTotalMB, sysRAMPercent := getSystemRAM()

	return HardwareStats{
		CPUPercent: a.getCPUPercent(),
		RAMMB:      ramMB,
		RAMTotalMB: sysTotalMB,
		RAMPercent: sysRAMPercent,
		Goroutines: goroutines,
	}
}

var (
	kernel32           = windows.NewLazySystemDLL("kernel32.dll")
	procGetSystemTimes = kernel32.NewProc("GetSystemTimes")
)

type memoryStatusEx struct {
	Length               uint32
	MemoryLoad           uint32
	TotalPhys            uint64
	AvailPhys            uint64
	TotalPageFile        uint64
	AvailPageFile        uint64
	TotalVirtual         uint64
	AvailVirtual         uint64
	ExtendedAvailVirtual uint64
}

func getSystemRAM() (totalMB, usedPercent float64) {
	procGlobalMemoryStatusEx := kernel32.NewProc("GlobalMemoryStatusEx")
	var ms memoryStatusEx
	ms.Length = uint32(unsafe.Sizeof(ms))
	ret, _, _ := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&ms)))
	if ret == 0 {
		return 0, 0
	}
	totalMB = float64(ms.TotalPhys) / 1024 / 1024
	usedPercent = float64(ms.MemoryLoad)
	return
}

func (a *App) getCPUPercent() float64 {
	a.cpuMu.Lock()
	defer a.cpuMu.Unlock()

	var idleFT, kernelFT, userFT windows.Filetime
	ret, _, _ := procGetSystemTimes.Call(
		uintptr(unsafe.Pointer(&idleFT)),
		uintptr(unsafe.Pointer(&kernelFT)),
		uintptr(unsafe.Pointer(&userFT)),
	)
	if ret == 0 {
		return 0
	}

	idle := uint64(idleFT.LowDateTime) | (uint64(idleFT.HighDateTime) << 32)
	kernel := uint64(kernelFT.LowDateTime) | (uint64(kernelFT.HighDateTime) << 32)
	user := uint64(userFT.LowDateTime) | (uint64(userFT.HighDateTime) << 32)

	if a.firstCPUCall {
		a.prevCPUIdle = idle
		a.prevCPUKernel = kernel
		a.prevCPUUser = user
		a.firstCPUCall = false
		return 0
	}

	idleDelta := idle - a.prevCPUIdle
	kernelDelta := kernel - a.prevCPUKernel
	userDelta := user - a.prevCPUUser

	totalDelta := kernelDelta + userDelta

	a.prevCPUIdle = idle
	a.prevCPUKernel = kernel
	a.prevCPUUser = user

	if totalDelta == 0 {
		return 0
	}

	return float64(totalDelta-idleDelta) / float64(totalDelta) * 100.0
}

func (a *App) shutdown() {
	a.appendLog("[shutdown] NovaProxy shutting down...")

	proxyRunning := a.IsProxyRunning()

	if a.core != nil {
		a.core.shutdownIfRunning()
	}

	if proxyRunning || a.proxyServer.IsRunning() {
		a.appendLog("[shutdown] Restoring original system proxy settings...")
		if err := sysproxy.RestoreOriginalProxySettings(); err != nil {
			a.appendLog("[shutdown] Failed to restore proxy settings: " + err.Error())
		}
		if err := a.clearManagedSystemProxyMarker(); err != nil {
			a.appendLog("[shutdown] Failed to clear managed system proxy marker: " + err.Error())
		}
	}

	if a.gsaManager != nil && a.gsaManager.IsRunning() {
		a.appendLog("[shutdown] Stopping GSA proxy...")
		if err := a.gsaManager.Stop(); err != nil {
			a.appendLog("[shutdown] GSA stop error: " + err.Error())
		}
	}

	a.appendLog("[shutdown] NovaProxy shutdown complete")
}

func (a *App) setupFileLogger() {
	if a.logBuffer == nil {
		a.logBuffer = newRingLogWriter(500)
	}
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.SetOutput(newBestEffortMultiWriter(&gatedLogWriter{app: a}, os.Stdout))
}

func (a *App) appendLog(message string) {
	if !a.IsLogCaptureEnabled() {
		return
	}
	if a.logBuffer == nil {
		a.logBuffer = newRingLogWriter(500)
	}
	trimmed := strings.TrimSpace(message)
	if trimmed == "" {
		return
	}
	// Force newline for ringLogWriter processing
	if !strings.HasSuffix(trimmed, "\n") {
		trimmed += "\n"
	}
	if matched, _ := regexp.MatchString(`^\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}`, trimmed); matched {
		a.logBuffer.Write([]byte(trimmed))
		return
	}
	formatted := time.Now().Format("2006/01/02 15:04:05.000000") + " " + trimmed
	a.logBuffer.Write([]byte(formatted))
}

func (a *App) GetRecentLogs(limit int) string {
	if a.core != nil {
		if logs := a.core.GetRecentLogs(limit); strings.TrimSpace(logs) != "" {
			return logs
		}
	}
	if limit <= 0 {
		limit = 200
	}
	if limit > 2000 {
		limit = 2000
	}

	if a.logBuffer != nil {
		lines := a.logBuffer.Snapshot(limit)
		if len(lines) > 0 {
			return strings.Join(lines, "\n")
		}
	}

	return ""
}

func (a *App) ClearLogs() error {
	if a.core != nil {
		_ = a.core.ClearLogs()
	}
	if a.logBuffer != nil {
		a.logBuffer.Clear()
	}
	return nil
}

func (a *App) IsLogCaptureEnabled() bool {
	if a.core != nil {
		if enabled := a.core.IsLogCaptureEnabled(); enabled {
			a.logCaptureMu.Lock()
			a.logCaptureEnabled = true
			a.logCaptureMu.Unlock()
			return true
		}
	}
	a.logCaptureMu.RLock()
	defer a.logCaptureMu.RUnlock()
	return a.logCaptureEnabled
}

func (a *App) StartLogCapture() error {
	if a.core != nil {
		if err := a.core.StartLogCapture(); err == nil {
			a.logCaptureMu.Lock()
			a.logCaptureEnabled = true
			a.logCaptureMu.Unlock()
			return nil
		}
	}
	if a.logBuffer == nil {
		a.logBuffer = newRingLogWriter(5000)
	}
	a.logBuffer.Clear()

	a.logCaptureMu.Lock()
	alreadyEnabled := a.logCaptureEnabled
	a.logCaptureEnabled = true
	a.logCaptureMu.Unlock()

	if !alreadyEnabled {
		a.appendLog("[logs] capture started")
	}
	return nil
}

func (a *App) StopLogCapture() error {
	if a.core != nil {
		_ = a.core.StopLogCapture()
	}
	if a.IsLogCaptureEnabled() {
		a.appendLog("[logs] capture stopping")
	}

	a.logCaptureMu.Lock()
	a.logCaptureEnabled = false
	a.logCaptureMu.Unlock()
	return nil
}

func (a *App) Greet(name string) string {
	return fmt.Sprintf("Hello %s, It's show time!", name)
}

func (a *App) StartProxy() error {
	if a.core != nil {
		err := a.core.StartProxy()
		if err != nil {
			return err
		}
		a.autoStartGSA()
		a.UpdateTrayMenu()
		a.refreshTrayMenuLater(300*time.Millisecond, time.Second)
		a.emitFrontendState()
		return nil
	}
	a.proxyOpMu.Lock()
	defer a.proxyOpMu.Unlock()

	a.appendLog("[action] StartProxy called")

	// 1. Get target port and check availability
	originalPort := a.GetListenPort()
	if originalPort == 0 {
		originalPort = 8080
	}

	availablePort, err := proxy.EnsurePortAvailable(originalPort, []string{"novaproxy", "usque"})
	if err != nil {
		a.appendLog(fmt.Sprintf("[warn] Port probe failed: %v, attempting with original port", err))
		availablePort = originalPort
	}

	// 2. If port changed, update config and notify user
	if availablePort != originalPort {
		a.appendLog(fmt.Sprintf("[info] Port %d was occupied. Switched to %d.", originalPort, availablePort))
		if err := a.SetListenPort(availablePort); err != nil {
			a.appendLog("[warn] Failed to update config with new port: " + err.Error())
		}
	}

	// 3. Actually start the core
	err = a.proxyServer.Start()
	if err != nil {
		msg := err.Error()
		if strings.Contains(msg, "Only one usage of each socket address") || strings.Contains(msg, "bind: address already in use") {
			msg += " (Core start failed: port still occupied, check permissions or manually kill process)"
		}
		a.appendLog("[error] StartProxy failed: " + msg)
		a.emitNotification("error", "Proxy Error", "Failed to start proxy: "+msg)
		return fmt.Errorf("%s", msg)
	}

	// Start process monitor for tracking connected apps
	if a.proxyServer.GetProcessMonitor() == nil {
		a.proxyServer.InitProcessMonitor()
	}

	a.emitNotification("success", "Proxy", "Proxy started successfully")
	a.UpdateTrayMenu()
	addr := a.proxyServer.GetListenAddr()
	if err := a.waitForProxyListen(addr, 2*time.Second); err != nil {
		_ = a.proxyServer.Stop()
		a.refreshTrayMenuLater(200 * time.Millisecond)
		a.appendLog("[error] StartProxy self-check failed: " + err.Error())
		return fmt.Errorf("proxy started but not listening on %s: %w", addr, err)
	}

	// 4. User feedback: if port drifted, auto-reset system proxy (if currently enabled)
	// Or as user requested: auto-set system proxy as soon as port drifted
	if availablePort != originalPort || a.GetSystemProxyStatus().Enabled {
		a.appendLog(fmt.Sprintf("[action] Syncing system proxy to port %d...", availablePort))
		_ = a.EnableSystemProxy()
	}

	a.autoStartGSA()

	a.refreshTrayMenuLater(300*time.Millisecond, time.Second)
	a.emitFrontendState()
	a.appendLog("[action] StartProxy success")
	return nil
}

func (a *App) autoStartGSA() {
	autoRoute := a.ruleManager.GetAutoRoutingConfig()
	a.appendLog(fmt.Sprintf("[GSA] autoStartGSA: mode=%s gsa_running=%v", autoRoute.Mode, a.gsaManager.IsRunning()))
	if autoRoute.Mode == "gsa" && !a.gsaManager.IsRunning() {
		a.appendLog("[GSA] Auto-routing mode is gsa — auto-starting GSA proxy")
		if err := a.gsaManager.Start(); err != nil {
			a.appendLog(fmt.Sprintf("[warn] GSA auto-start failed: %v", err))
		} else {
			cfg := a.gsaManager.GetConfig()
			a.appendLog(fmt.Sprintf("[GSA] autoStartGSA: Start() ok, running=%v, listening on port %d", cfg.Running, cfg.ListenPort))
			a.setGSADialAddr(fmt.Sprintf("127.0.0.1:%d", cfg.ListenPort))
			a.appendLog("[GSA] Auto-start succeeded")
		}
	} else {
		a.appendLog(fmt.Sprintf("[GSA] autoStartGSA: skipped (mode=%s, already_running=%v)", autoRoute.Mode, a.gsaManager.IsRunning()))
	}
}

func (a *App) StopProxy() error {
	a.emitNotification("info", "Proxy", "Proxy stopping...")
	if a.core != nil {
		err := a.core.StopProxy()
		if a.GetSystemProxyStatus().Enabled {
			_ = a.DisableSystemProxy()
		}
		a.UpdateTrayMenu()
		a.refreshTrayMenuLater(300 * time.Millisecond)
		a.emitFrontendState()
		return err
	}
	a.proxyOpMu.Lock()
	defer a.proxyOpMu.Unlock()

	a.appendLog("[action] StopProxy called")

	var errs []error

	if err := a.proxyServer.Stop(); err != nil {
		a.appendLog("[error] StopProxy failed: " + err.Error())
		errs = append(errs, err)
	}

	a.proxyServer.StopProcessMonitor()

	// Auto-stop GSA when main proxy stops
	if a.gsaManager.IsRunning() {
		a.appendLog("[GSA] Auto-stopping GSA proxy with main proxy")
		a.setGSADialAddr("")
		if err := a.gsaManager.Stop(); err != nil {
			a.appendLog(fmt.Sprintf("[warn] GSA auto-stop failed: %v", err))
		}
	}
	a.UpdateTrayMenu()

	if a.GetSystemProxyStatus().Enabled {
		if err := a.DisableSystemProxy(); err != nil {
			a.appendLog("[error] DisableSystemProxy during StopProxy failed: " + err.Error())
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		a.emitNotification("error", "Proxy Error", "Failed to stop proxy")
		a.refreshTrayMenuLater(300 * time.Millisecond)
		a.emitFrontendState()
		return errors.Join(errs...)
	}
	a.emitNotification("info", "Proxy", "Proxy stopped")
	a.refreshTrayMenuLater(300 * time.Millisecond)
	a.emitFrontendState()
	a.appendLog("[action] StopProxy success")
	return nil
}

func (a *App) IsProxyRunning() bool {
	if a.core != nil {
		return a.core.IsProxyRunning()
	}
	return a.proxyServer.IsRunning()
}

func (a *App) GetStats() (int64, int64, int64) {
	if a.core != nil {
		return a.core.GetStats()
	}
	return a.proxyServer.GetStats()
}

func (a *App) GetListenAddr() string {
	return a.proxyServer.GetListenAddr()
}

func (a *App) SetListenAddr(addr string) error {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid address %q: %w", addr, err)
	}
	if portStr != "" {
		var port int
		if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil || port < 1 || port > 65535 {
			return fmt.Errorf("invalid port in address %q", addr)
		}
	}
	if err := a.proxyServer.SetListenAddr(addr); err != nil {
		return err
	}
	a.ruleManager.SetListenHost(host)
	a.ruleManager.SetListenPort(portStr)
	if err := a.ruleManager.SaveConfig(); err != nil {
		return err
	}
	if a.core != nil {
		a.core.reloadIfRunning()
	}
	return nil
}

func (a *App) GetListenPort() int {
	addr := a.proxyServer.GetListenAddr()
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	var port int
	fmt.Sscanf(portStr, "%d", &port)
	return port
}

func (a *App) SetListenPort(port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("invalid port number: %d", port)
	}
	host := a.ruleManager.GetListenHost()
	if host == "" {
		host = "127.0.0.1"
	}
	addr := fmt.Sprintf("%s:%d", host, port)
	err := a.proxyServer.SetListenAddr(addr)
	if err != nil {
		return err
	}
	a.ruleManager.SetListenPort(fmt.Sprintf("%d", port))
	if err := a.ruleManager.SaveConfig(); err != nil {
		return err
	}
	if a.core != nil {
		a.core.reloadIfRunning()
	}
	return nil
}

func (a *App) SetSOCKSAddr(addr string) error {
	if err := a.proxyServer.SetSOCKSAddr(addr); err != nil {
		return err
	}
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid SOCKS5 address %q: %w", addr, err)
	}
	a.ruleManager.SetSocksAddr(addr)
	a.ruleManager.SetSocksHost(host)
	a.ruleManager.SetSocksPort(portStr)
	if err := a.ruleManager.SaveConfig(); err != nil {
		return err
	}
	if a.core != nil {
		a.core.reloadIfRunning()
	}
	return nil
}

func (a *App) SetProxyMode(mode string) error {
	a.appendLog("[action] SetProxyMode: " + mode)
	if a.core != nil {
		if err := a.core.SetProxyMode(mode); err != nil {
			a.appendLog("[error] SetProxyMode failed: " + err.Error())
			return err
		}
	}
	err := a.proxyServer.SetMode(mode)
	if err != nil {
		a.appendLog("[error] SetProxyMode failed: " + err.Error())
	}
	return err
}

func (a *App) GetProxyMode() string {
	if a.core != nil {
		if mode := a.core.GetProxyMode(); strings.TrimSpace(mode) != "" {
			return mode
		}
	}
	return a.proxyServer.GetMode()
}

func (a *App) GetTUNConfig() proxy.TUNConfig {
	if a.ruleManager == nil {
		return proxy.TUNConfig{}
	}
	return a.ruleManager.GetTUNConfig()
}

func (a *App) UpdateTUNConfig(cfg proxy.TUNConfig) error {
	if a.ruleManager == nil {
		return fmt.Errorf("RuleManager not initialized")
	}
	cfg = proxy.TUNConfig{
		MTU:         cfg.MTU,
		DNSHijack:   cfg.DNSHijack,
		AutoRoute:   cfg.AutoRoute,
		StrictRoute: cfg.StrictRoute,
	}
	if err := a.ruleManager.UpdateTUNConfig(cfg); err != nil {
		a.appendLog("[error] UpdateTUNConfig failed: " + err.Error())
		return err
	}
	if a.core != nil {
		a.core.reloadIfRunning()
	}
	a.emitFrontendState()
	a.appendLog(fmt.Sprintf("[action] TUN config updated: mtu=%d", cfg.MTU))
	return nil
}

func (a *App) GetTUNStatus() proxy.TUNStatus {
	if a.core != nil {
		return a.core.GetTUNStatus()
	}
	return proxy.TUNStatus{}
}

// --- DNS Node API ---

func (a *App) GetDNSNodes() []proxy.DNSNode {
	if a.ruleManager == nil {
		return []proxy.DNSNode{}
	}
	return a.ruleManager.GetDNSNodes()
}

func (a *App) AddDNSNode(n proxy.DNSNode) error {
	if a.ruleManager == nil {
		return fmt.Errorf("RuleManager not initialized")
	}
	a.emitNotification("info", "DNS", "DNS node added: "+n.Name)
	return a.ruleManager.AddDNSNode(n)
}

func (a *App) UpdateDNSNode(n proxy.DNSNode) error {
	if a.ruleManager == nil {
		return fmt.Errorf("RuleManager not initialized")
	}
	a.emitNotification("info", "DNS", "DNS node updated: "+n.Name)
	return a.ruleManager.UpdateDNSNode(n)
}

func (a *App) DeleteDNSNode(id string) error {
	if a.ruleManager == nil {
		return fmt.Errorf("RuleManager not initialized")
	}
	a.emitNotification("info", "DNS", "DNS node deleted")
	return a.ruleManager.DeleteDNSNode(id)
}

func (a *App) SetDNSNodePriority(id string, targetIndex int) error {
	if a.ruleManager == nil {
		return fmt.Errorf("RuleManager not initialized")
	}
	return a.ruleManager.SetDNSNodePriority(id, targetIndex)
}

type DNSTestResult struct {
	Success bool     `json:"success"`
	IPs     []string `json:"ips,omitempty"`
	Latency string   `json:"latency,omitempty"`
	Error   string   `json:"error,omitempty"`
}

func (a *App) TestDNSNode(nodeID string) DNSTestResult {
	if a.ruleManager == nil {
		return DNSTestResult{Error: "RuleManager not initialized"}
	}

	nodes := a.ruleManager.GetDNSNodes()
	var target *proxy.DNSNode
	for i := range nodes {
		if nodes[i].ID == nodeID {
			target = &nodes[i]
			break
		}
	}
	if target == nil {
		return DNSTestResult{Error: "DNS node not found"}
	}

	if a.proxyServer == nil {
		return DNSTestResult{Error: "Core service not running, cannot test"}
	}
	resolver := a.proxyServer.GetDoHResolver()
	if resolver == nil {
		return DNSTestResult{Error: "Resolver not initialized"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	start := time.Now()
	ips, err := resolver.TestNode(ctx, *target)
	elapsed := time.Since(start)

	if err != nil {
		return DNSTestResult{Error: err.Error()}
	}
	return DNSTestResult{
		Success: len(ips) > 0,
		IPs:     ips,
		Latency: fmt.Sprintf("%dms", elapsed.Milliseconds()),
	}
}

func (a *App) PreviewTUNFlow(flow proxy.TUNFlow) proxy.TUNFlowPlan {
	if a.proxyServer == nil {
		return proxy.TUNFlowPlan{}
	}
	return a.proxyServer.PlanTUNFlow(flow)
}

func (a *App) StartTUN() (err error) {
	if a.core == nil {
		return fmt.Errorf("core client not initialized")
	}

	// TUN requires the proxy to be running first (mihomo forwards traffic to it)
	if !a.IsProxyRunning() {
		a.appendLog("[TUN] Proxy not running, starting it first...")
		if err := a.StartProxy(); err != nil {
			return fmt.Errorf("failed to start proxy before TUN: %w", err)
		}
	}

	captureEnabled := a.IsLogCaptureEnabled()
	err = a.core.StartTUN()
	if err == nil && captureEnabled {
		_ = a.core.StartLogCapture()
	}
	a.emitFrontendState()
	if err != nil {
		a.appendLog("[error] StartTUN failed: " + err.Error())
		a.emitNotification("error", "TUN Error", "Failed to start TUN: "+err.Error())
	} else {
		a.emitNotification("success", "TUN", "TUN mode enabled")
	}
	return err
}

func (a *App) StopTUN() error {
	a.emitNotification("info", "TUN", "TUN mode disabled")
	if a.core != nil {
		err := a.core.StopTUN()
		a.emitFrontendState()
		if err != nil {
			a.appendLog("[error] StopTUN failed: " + err.Error())
		}
		return err
	}
	return fmt.Errorf("core client not initialized")
}

func (a *App) GetCACertPath() string {
	if a.certManager == nil && a.certPath != "" {
		if cm, err := cert.InitCertManager(a.certPath); err == nil {
			a.certManager = cm
		}
	}
	if a.certManager != nil {
		return a.certManager.GetCACertPath()
	}
	return ""
}

type CAInstallStatus struct {
	Installed   bool
	Platform    string
	CertPath    string
	InstallHelp string
}

func (a *App) GetCAInstallStatus() CAInstallStatus {
	if a.certManager == nil {
		if a.certPath != "" {
			if cm, err := cert.InitCertManager(a.certPath); err == nil {
				a.certManager = cm
			}
		}
	}
	if a.certManager == nil {
		return CAInstallStatus{
			CertPath:    a.certPath,
			Platform:    "windows",
			InstallHelp: "در حال راه‌اندازی گواهی",
		}
	}
	status := a.certManager.GetCAInstallStatus()
	return CAInstallStatus{
		Installed:   status.Installed,
		Platform:    status.Platform,
		CertPath:    status.CertPath,
		InstallHelp: status.InstallHelp,
	}
}

func (a *App) OpenCAFile() error {
	if a.certManager == nil {
		a.appendLog("[cert] OpenCAFile failed: cert manager not initialized")
		return fmt.Errorf("cert manager not initialized")
	}
	a.appendLog("[cert] OpenCAFile called")
	if err := a.certManager.OpenCAFile(); err != nil {
		a.appendLog("[cert] OpenCAFile failed: " + err.Error())
		return err
	}
	a.appendLog("[cert] OpenCAFile succeeded")
	return nil
}

func (a *App) OpenCertDir() error {
	if a.certManager == nil {
		a.appendLog("[cert] OpenCertDir failed: cert manager not initialized")
		return fmt.Errorf("cert manager not initialized")
	}
	a.appendLog("[cert] OpenCertDir called")
	if err := a.certManager.OpenCertDir(); err != nil {
		a.appendLog("[cert] OpenCertDir failed: " + err.Error())
		return err
	}
	a.appendLog("[cert] OpenCertDir succeeded")
	return nil
}

func (a *App) InstallCA() error {
	if a.certManager == nil {
		a.appendLog("[cert] InstallCA failed: cert manager not initialized")
		return fmt.Errorf("cert manager not initialized")
	}
	a.appendLog("[cert] InstallCA called")
	if err := a.certManager.InstallCA(); err != nil {
		a.appendLog("[cert] InstallCA failed: " + err.Error())
		return err
	}
	a.proxyServer.ClearCertCache()
	if a.core != nil {
		a.core.reloadCertificateIfRunning()
	}
	a.emitNotification("success", "Certificate", "Root CA certificate installed successfully")
	a.appendLog("[cert] InstallCA succeeded")
	return nil
}

func (a *App) GetCACertPEM() string {
	if a.certManager != nil {
		return a.certManager.GetCACertPEM()
	}
	return ""
}

func (a *App) RegenerateCert() error {
	if a.certManager == nil {
		a.appendLog("[cert] RegenerateCert failed: cert manager not initialized")
		return fmt.Errorf("cert manager not initialized")
	}
	a.appendLog("[cert] RegenerateCert called")
	if err := a.certManager.RegenerateCA(); err != nil {
		a.appendLog("[cert] RegenerateCert failed: " + err.Error())
		return err
	}
	a.proxyServer.ClearCertCache()
	if a.core != nil {
		a.core.reloadCertificateIfRunning()
	}
	a.appendLog("[cert] RegenerateCert succeeded")
	return nil
}

func (a *App) ExportCert() string {
	if a.certManager == nil {
		return ""
	}
	data, err := a.certManager.ExportCert()
	if err != nil {
		a.appendLog("Export cert error: " + err.Error())
		return ""
	}
	return string(data)
}

func (a *App) GetInstalledCerts() []cert.InstalledCert {
	if a.certManager == nil {
		if a.certPath != "" {
			if cm, err := cert.InitCertManager(a.certPath); err == nil {
				a.certManager = cm
			}
		}
	}
	if a.certManager == nil {
		a.appendLog("[cert] GetInstalledCerts failed: cert manager not initialized")
		return []cert.InstalledCert{}
	}
	a.appendLog("[cert] GetInstalledCerts called")
	certs, err := a.certManager.GetInstalledCertificates()
	if err != nil {
		a.appendLog("GetInstalledCertificates error: " + err.Error())
		return []cert.InstalledCert{}
	}
	a.appendLog(fmt.Sprintf("[cert] GetInstalledCerts succeeded: %d certs", len(certs)))
	return certs
}

func (a *App) UninstallCert(thumbprint string) error {
	if a.certManager == nil {
		a.appendLog("[cert] UninstallCert failed: cert manager not initialized")
		return fmt.Errorf("cert manager not initialized")
	}
	a.appendLog("[cert] UninstallCert called: " + thumbprint)
	if err := a.certManager.UninstallCertificate(thumbprint); err != nil {
		a.appendLog("[cert] UninstallCert failed: " + err.Error())
		return err
	}
	a.appendLog("[cert] UninstallCert succeeded: " + thumbprint)
	return nil
}

func (a *App) GetSiteGroups() []proxy.SiteGroup {
	return a.ruleManager.GetSiteGroups()
}

func (a *App) AddSiteGroup(sg proxy.SiteGroup) error {
	a.emitNotification("info", "Rules", "Site rule added: "+sg.Name)
	return a.ruleManager.AddSiteGroup(sg)
}

func (a *App) UpdateSiteGroup(sg proxy.SiteGroup) error {
	a.emitNotification("info", "Rules", "Site rule updated: "+sg.Name)
	return a.ruleManager.UpdateSiteGroup(sg)
}

func (a *App) DeleteSiteGroup(id string) error {
	a.emitNotification("info", "Rules", "Site rule deleted")
	return a.ruleManager.DeleteSiteGroup(id)
}

func (a *App) GetUpstreams() []proxy.Upstream {
	return a.ruleManager.GetUpstreams()
}

func (a *App) AddUpstream(u proxy.Upstream) error {
	return a.ruleManager.AddUpstream(u)
}

func (a *App) UpdateUpstream(u proxy.Upstream) error {
	return a.ruleManager.UpdateUpstream(u)
}

func (a *App) DeleteUpstream(id string) error {
	return a.ruleManager.DeleteUpstream(id)
}

func (a *App) GetCloudflareConfig() proxy.CloudflareConfig {
	return a.ruleManager.GetCloudflareConfig()
}

func (a *App) GetECHProfiles() []proxy.ECHProfile {
	return a.ruleManager.GetECHProfiles()
}

func (a *App) UpsertECHProfile(p proxy.ECHProfile) error {
	return a.ruleManager.UpsertECHProfile(p)
}

func (a *App) DeleteECHProfile(id string) error {
	return a.ruleManager.DeleteECHProfile(id)
}

func (a *App) GetServerConfig() map[string]string {
	res := map[string]string{
		"host": "",
		"auth": "",
	}
	if a.ruleManager != nil {
		res["host"] = a.ruleManager.GetServerHost()
		res["auth"] = a.ruleManager.GetServerAuth()
	}
	return res
}

func (a *App) UpdateServerConfig(host, auth string) error {
	if a.ruleManager != nil {
		err := a.ruleManager.UpdateServerConfig(strings.TrimSpace(host), strings.TrimSpace(auth))
		if err == nil {
			a.appendLog(fmt.Sprintf("[INFO] Updated Server Worker settings, Host: %s", host))
			if a.core != nil {
				a.core.reloadIfRunning()
			}
		} else {
			a.appendLog(fmt.Sprintf("[ERROR] Failed to save Server settings: %v", err))
		}
		return err
	}
	return fmt.Errorf("RuleManager not initialized")
}

func (a *App) UpdateCloudflareConfig(cfg proxy.CloudflareConfig) error {
	oldCfg := a.ruleManager.GetCloudflareConfig()

	err := a.ruleManager.UpdateCloudflareConfig(cfg)
	if err == nil {
		a.proxyServer.UpdateCloudflareConfig(cfg)
		if a.core != nil {
			a.core.reloadIfRunning()
		}
		if cfg.AutoUpdate && !oldCfg.AutoUpdate {
			a.appendLog("[Cloudflare] Auto update enabled, triggering fetch...")
			go a.RefreshCloudflareIPPool()
		}
		a.UpdateTrayMenu()
	}
	return err
}

func (a *App) RefreshCloudflareIPPool() {
	cfg := a.ruleManager.GetCloudflareConfig()
	ips, err := proxy.FetchCloudflareIPs(cfg.APIKey)
	if err != nil {
		log.Printf("[Cloudflare] Failed to fetch preferred IPs: %v", err)
		a.appendLog("[error] Cloudflare preferred IP fetch failed: " + err.Error())
		return
	}

	if len(ips) > 0 {
		log.Printf("[Cloudflare] Successfully fetched %d preferred IPs", len(ips))
		a.appendLog(fmt.Sprintf("[success] Successfully fetched %d Cloudflare preferred IPs", len(ips)))

		a.proxyServer.UpdateCloudflareIPPool(ips)
			// Persistence: sync to config file
		cfg.PreferredIPs = ips
		_ = a.ruleManager.UpdateCloudflareConfig(cfg)
		if a.core != nil {
			a.core.reloadIfRunning()
		}
	}
}

func (a *App) ForceFetchCloudflareIPs() error {
	cfg := a.ruleManager.GetCloudflareConfig()
	ips, err := proxy.FetchCloudflareIPs(cfg.APIKey)
	if err != nil {
		log.Printf("[Cloudflare] Failed to fetch preferred IPs: %v", err)
		a.appendLog("[error] Manual fetch failed: " + err.Error())
		return err
	}

	if len(ips) > 0 {
		log.Printf("[Cloudflare] Successfully fetched %d preferred IPs", len(ips))
		a.appendLog(fmt.Sprintf("[success] Successfully fetched %d Cloudflare preferred IPs", len(ips)))
		a.proxyServer.UpdateCloudflareIPPool(ips)
		// Persistence: sync to config file
		cfg.PreferredIPs = ips
		_ = a.ruleManager.UpdateCloudflareConfig(cfg)
		if a.core != nil {
			a.core.reloadIfRunning()
		}
		// Trigger immediate health check to update stats
		a.proxyServer.TriggerCFHealthCheck()
	}
	return nil
}

func (a *App) GetCloudflareIPStats() []*proxy.IPStats {
	return a.proxyServer.GetAllCFIPsWithStats()
}

func (a *App) ExportConfig() (string, error) {
	return a.ruleManager.ExportConfig()
}

func (a *App) TestServerNode() (int64, error) {
	a.appendLog("[TestNode] Clicked - Checking configuration...")
	host := a.ruleManager.GetServerHost()
	auth := a.ruleManager.GetServerAuth()
	if host == "" || auth == "" {
		a.appendLog("[TestNode] Error: Server host or auth NOT configured. Please click 'Save' first.")
		return 0, fmt.Errorf("Server node NOT configured")
	}

	a.appendLog("[TestNode] Config OK. Host: " + host)

	// Process host format to prevent duplicate protocol header
	cleanHost := strings.TrimSpace(host)
	if !strings.HasPrefix(cleanHost, "http://") && !strings.HasPrefix(cleanHost, "https://") {
		cleanHost = "https://" + cleanHost
	}
	cleanHost = strings.TrimSuffix(cleanHost, "/")

	// Construct test target
	testTarget := "https://www.google.com/generate_204"
	u, _ := url.Parse(testTarget)

	workerUrl := fmt.Sprintf("%s/%s/%s%s", cleanHost, auth, u.Host, u.Path)
	if u.RawQuery != "" {
		workerUrl += "?" + u.RawQuery
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	start := time.Now()
	log.Printf("[TestNode] Testing server node via URL: %s", workerUrl)
	resp, err := client.Get(workerUrl)
	if err != nil {
		log.Printf("[TestNode] HTTP Request failed: %v", err)
		return 0, err
	}
	defer resp.Body.Close()

	duration := time.Since(start).Milliseconds()
	log.Printf("[TestNode] Server responded with status: %d, latency: %dms", resp.StatusCode, duration)

	// User requirement: only status 200 (or 204) counts as connected
	if resp.StatusCode != 200 && resp.StatusCode != 204 {
		return 0, fmt.Errorf("Server returned non-200 status: %d", resp.StatusCode)
	}

	return duration, nil
}

func (a *App) ImportConfig(content string) error {
	return a.ruleManager.ImportConfig(content)
}

func (a *App) ImportConfigWithSummary(content string) (proxy.ImportSummary, error) {
	return a.ruleManager.ImportConfigWithSummary(content)
}

type SystemProxyStatus struct {
	Enabled  bool
	Server   string
	Override string
}

type ProxyDiagnostics struct {
	Accepted      int64
	Requests      int64
	Connects      int64
	RecentIngress []string
}

func (a *App) TriggerCFHealthCheck() {
	a.proxyServer.TriggerCFHealthCheck()
	a.appendLog("[Cloudflare] Manual trigger IP health check...")
}

func (a *App) RemoveInvalidCFIPs() int {
	count := a.proxyServer.RemoveInvalidCFIPs()
	a.appendLog(fmt.Sprintf("[Cloudflare] Cleaned up %d invalid IPs", count))
	return count
}

func (a *App) GetSystemProxyStatus() SystemProxyStatus {
	status := sysproxy.GetSystemProxyStatus()
	return SystemProxyStatus{
		Enabled:  status.Enabled,
		Server:   status.Server,
		Override: status.Override,
	}
}

func (a *App) applySystemProxy(enabled bool, port int) error {
	a.systemProxyOpMu.Lock()
	defer a.systemProxyOpMu.Unlock()

	status := a.GetSystemProxyStatus()

	if enabled {
		expected := fmt.Sprintf("127.0.0.1:%d", port)
		if status.Enabled && strings.EqualFold(strings.TrimSpace(status.Server), expected) {
			if err := a.saveManagedSystemProxyMarker(expected); err != nil {
				a.appendLog("[warn] Failed to save managed system proxy marker: " + err.Error())
			}
			a.appendLog("[action] EnableSystemProxy skipped: already enabled")
			a.UpdateTrayMenu()
			a.emitFrontendState()
			return nil
		}
		if err := sysproxy.EnableSystemProxy(port); err != nil {
			return err
		}
		if err := a.saveManagedSystemProxyMarker(expected); err != nil {
			a.appendLog("[warn] Failed to save managed system proxy marker: " + err.Error())
		}
	} else {
		if !status.Enabled {
			if err := a.clearManagedSystemProxyMarker(); err != nil {
				a.appendLog("[warn] Failed to clear managed system proxy marker: " + err.Error())
			}
			a.appendLog("[action] DisableSystemProxy skipped: already disabled")
			a.UpdateTrayMenu()
			a.emitFrontendState()
			return nil
		}
		if err := sysproxy.DisableSystemProxy(); err != nil {
			return err
		}
		if err := a.clearManagedSystemProxyMarker(); err != nil {
			a.appendLog("[warn] Failed to clear managed system proxy marker: " + err.Error())
		}
	}

	a.UpdateTrayMenu()
	a.refreshTrayMenuLater(300 * time.Millisecond)
	a.emitFrontendState()
	return nil
}

func (a *App) EnableSystemProxy() error {
	a.appendLog("[action] EnableSystemProxy called")

	if !a.IsProxyRunning() {
		a.appendLog("[action] Proxy not running, starting proxy before enabling system proxy...")
		if err := a.StartProxy(); err != nil {
			a.appendLog("[error] EnableSystemProxy failed to auto-start proxy: " + err.Error())
			return err
		}
	}

	addr := a.proxyServer.GetListenAddr()
	var port int
	_, portStr, err := net.SplitHostPort(addr)
	if err == nil {
		fmt.Sscanf(portStr, "%d", &port)
	}
	if port == 0 {
		port = 8080
	}
	if err := a.waitForProxyListen(addr, 500*time.Millisecond); err != nil {
		a.appendLog("[warn] EnableSystemProxy probe timeout (expected if already running): " + err.Error())
	}
	err = a.applySystemProxy(true, port)
	if err != nil {
		a.appendLog("[error] EnableSystemProxy failed: " + err.Error())
		return err
	}
	a.emitNotification("success", "System Proxy", "System proxy enabled")
	a.appendLog(fmt.Sprintf("[action] EnableSystemProxy success: 127.0.0.1:%d", port))
	return nil
}

func (a *App) DisableSystemProxy() error {
	a.appendLog("[action] DisableSystemProxy called")
	err := a.applySystemProxy(false, 0)
	if err != nil {
		a.appendLog("[error] DisableSystemProxy failed: " + err.Error())
		return err
	}
	a.emitNotification("info", "System Proxy", "System proxy disabled")
	a.appendLog("[action] DisableSystemProxy success")
	return nil
}

func (a *App) waitForProxyListen(addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond) // Faster dial
		if err == nil {
			_ = conn.Close()
			return nil
		}
		lastErr = err
		time.Sleep(20 * time.Millisecond) // Faster retry
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("timeout")
	}
	return lastErr
}

func (a *App) GetSOCKSAddr() string {
	return a.proxyServer.GetSOCKSAddr()
}

func (a *App) GetProxyDiagnostics() map[string]interface{} {
	return map[string]interface{}{
		"ListenAddr": a.proxyServer.GetListenAddr(),
		"SOCKSAddr":  a.proxyServer.GetSOCKSAddr(),
		"Status":     "OK",
	}
}

func (a *App) ProxySelfCheck() string {
	addr := a.proxyServer.GetListenAddr()
	a.appendLog("[diag] ProxySelfCheck started via " + addr)

	if !a.proxyServer.IsRunning() {
		msg := "[diag] ProxySelfCheck failed: proxy not running"
		a.appendLog(msg)
		return msg
	}

	proxyURL, err := url.Parse("http://" + addr)
	if err != nil {
		msg := "[diag] ProxySelfCheck failed: invalid proxy addr: " + err.Error()
		a.appendLog(msg)
		return msg
	}

	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		DialContext: (&net.Dialer{
			Timeout:   6 * time.Second,
			KeepAlive: 10 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   8 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   15 * time.Second,
	}

	req, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
	if err != nil {
		msg := "[diag] ProxySelfCheck failed: " + err.Error()
		a.appendLog(msg)
		return msg
	}

	resp, err := client.Do(req)
	if err != nil {
		msg := "[diag] ProxySelfCheck failed: " + err.Error()
		a.appendLog(msg)
		return msg
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 2048))

	msg := fmt.Sprintf("[diag] ProxySelfCheck success: status=%d", resp.StatusCode)
	a.appendLog(msg)
	return msg
}

func (a *App) FetchECHConfig(domain string, dohURL string) (string, error) {
	a.appendLog(fmt.Sprintf("[DoH] Fetching ECH for %s via %s", domain, dohURL))

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	config, err := a.proxyServer.FetchECH(ctx, domain, dohURL)
	if err != nil {
		a.appendLog(fmt.Sprintf("[error] ECH fetch failed: %v", err))
		return "", err
	}

	if len(config) == 0 {
		return "", fmt.Errorf("no ECH config found")
	}

	encoded := base64.StdEncoding.EncodeToString(config)
	a.appendLog(fmt.Sprintf("[success] ECH fetch ok (%d bytes)", len(config)))
	return encoded, nil
}

// --- Auto Routing API ---

func (a *App) GetAutoRoutingConfig() proxy.AutoRoutingConfig {
	return a.ruleManager.GetAutoRoutingConfig()
}

func (a *App) UpdateAutoRoutingConfig(cfg proxy.AutoRoutingConfig) error {
	a.appendLog(fmt.Sprintf("[AutoRoute] Updating config: mode=%s", cfg.Mode))
	err := a.ruleManager.UpdateAutoRoutingConfig(cfg)
	if err != nil {
		a.appendLog("[AutoRoute] Config update failed: " + err.Error())
		a.emitNotification("error", "Routing", "Failed to update routing config: "+err.Error())
		return err
	}
	a.emitNotification("info", "Routing", "Auto routing config updated")
	if a.core != nil {
		a.core.reloadIfRunning()
	}
	// If auto routing is enabled and no GFW list loaded, trigger fetch
	if cfg.Mode != "" {
		status := a.ruleManager.GetAutoRoutingStatus()
		if status.DomainCount == 0 {
			go func() {
				a.appendLog("[AutoRoute] No GFW list loaded, fetching...")
				_, _ = a.RefreshGFWList()
			}()
		}
	}

	// Auto-start/stop GSA based on mode (if proxy is running)
	proxyRunning := a.proxyServer.IsRunning()
	a.appendLog(fmt.Sprintf("[GSA] UpdateAutoRouting: mode=%s proxy_running=%v gsa_running=%v",
		cfg.Mode, proxyRunning, a.gsaManager.IsRunning()))
	if proxyRunning {
		if cfg.Mode == "gsa" && !a.gsaManager.IsRunning() {
			a.appendLog("[GSA] Auto-routing mode changed to gsa — starting GSA proxy")
			if startErr := a.gsaManager.Start(); startErr != nil {
				a.appendLog(fmt.Sprintf("[warn] GSA auto-start failed: %v", startErr))
				a.emitNotification("error", "GSA", "Failed to start GSA: "+startErr.Error())
			} else {
				gsaCfg := a.gsaManager.GetConfig()
				a.appendLog(fmt.Sprintf("[GSA] UpdateAutoRouting: Start() ok, running=%v", gsaCfg.Running))
				a.setGSADialAddr(fmt.Sprintf("127.0.0.1:%d", gsaCfg.ListenPort))
				a.appendLog("[GSA] Auto-start succeeded")
				a.emitNotification("info", "GSA", "GSA proxy started")
			}
		} else if cfg.Mode != "gsa" && a.gsaManager.IsRunning() {
			a.appendLog("[GSA] Auto-routing mode changed from gsa — stopping GSA proxy")
			a.setGSADialAddr("")
			if stopErr := a.gsaManager.Stop(); stopErr != nil {
				a.appendLog(fmt.Sprintf("[warn] GSA auto-stop failed: %v", stopErr))
			} else {
				a.appendLog("[GSA] Auto-stop succeeded")
				a.emitNotification("info", "GSA", "GSA proxy stopped")
			}
		} else {
			a.appendLog(fmt.Sprintf("[GSA] UpdateAutoRouting: no GSA action needed (mode=%s gsa_running=%v)",
				cfg.Mode, a.gsaManager.IsRunning()))
		}
	}

	return nil
}

func (a *App) GetAutoRoutingStatus() proxy.GFWListStatus {
	return a.ruleManager.GetAutoRoutingStatus()
}

func (a *App) RefreshGFWList() (int, error) {
	a.appendLog("[AutoRoute] Refreshing GFW list...")
	count, err := a.ruleManager.RefreshGFWList()
	if err != nil {
		a.appendLog("[AutoRoute] GFW list refresh failed: " + err.Error())
		return 0, err
	}
	a.appendLog(fmt.Sprintf("[AutoRoute] GFW list refreshed: %d domains loaded", count))
	return count, nil
}

// Window Management API - Deeper Fix for v3
func (a *App) WindowMinimise() {
	if a.mainWindow != nil {
		a.mainWindow.Minimise()
	}
}

func (a *App) WindowToggleMaximise() {
	if a.mainWindow != nil {
		a.mainWindow.ToggleMaximise()
	}
}

func (a *App) WindowClose() {
	a.QuitApp()
}

func (a *App) GetActiveProcesses() []proxy.ProcessInfo {
	pm := a.proxyServer.GetProcessMonitor()
	if pm == nil {
		return nil
	}
	return pm.GetProcesses()
}
