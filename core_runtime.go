package main

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"novaproxy/cert"
	"novaproxy/proxy"
)

// logBufPool provides reusable byte buffers for log formatting
// to reduce memory allocation and GC pressure in high-frequency logging.
var logBufPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, 0, 256)
		return &buf
	},
}

type coreRuntime struct {
	mu                sync.RWMutex
	execPath          string
	execDir           string
	certPath          string
	ruleManager       *proxy.RuleManager
	proxyServer       *proxy.ProxyServer
	externalTUN       *externalMihomoManager
	certManager       *cert.CertManager
	logBuffer         *ringLogWriter
	logCaptureMu      sync.RWMutex
	logCaptureEnabled bool
	proxyOpMu         sync.Mutex
	tunStateMu        sync.RWMutex
	tunStarting       bool
	tunStartErr       string
	routeEventsMu     sync.Mutex
	routeEvents       []RouteEvent
}

func newCoreRuntime() (*coreRuntime, error) {
	execPath, err := os.Executable()
	if err != nil {
		return nil, err
	}
	execDir := filepath.Dir(execPath)
	settingsPath := resolveRuntimeFile(execDir, filepath.Join("data", "config", "settings.json"))
	rulesPath := resolveRuntimeFile(execDir, filepath.Join("data", "rules", "config.json"))

	ruleManager := proxy.NewRuleManager(settingsPath, rulesPath)
	if err := ruleManager.LoadConfig(); err != nil {
		return nil, err
	}

	port := ruleManager.GetListenPort()
	if port == "" {
		port = "8080"
	}

	r := &coreRuntime{
		execPath:    execPath,
		execDir:     execDir,
		certPath:    filepath.Join(execDir, "data", "cert"),
		ruleManager: ruleManager,
		proxyServer: proxy.NewProxyServer("127.0.0.1:" + port),
		externalTUN: newExternalMihomoManager(),
		logBuffer:   newRingLogWriter(5000),
	}

	if err := r.proxyServer.SetSOCKSAddr(ruleManager.GetSocksAddr()); err != nil {
		r.appendLog("[warn] Failed to set SOCKS5 address: " + err.Error())
	}

	if err := r.start(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *coreRuntime) start() error {
	writeCoreMarker(r.execDir, "core_runtime_start", "begin")
	r.setupLogger()
	var err error
	r.certManager, err = cert.InitCertManager(r.certPath)
	if err != nil {
		r.appendLog("[core] Failed to init cert manager: " + err.Error())
	}
	r.proxyServer.SetRuleManager(r.ruleManager)
	r.proxyServer.UpdateCloudflareConfig(r.ruleManager.GetCloudflareConfig())
	r.proxyServer.SetCertGenerator(r.certManager)
	r.proxyServer.SetLogCallback(r.appendLog)
	r.ruleManager.InitAutoRouter(r.proxyServer.GetDoHResolver())

	r.ruleManager.SetRouteEventCallback(func(domain, mode string) {
		r.routeEventsMu.Lock()
		defer r.routeEventsMu.Unlock()
		r.routeEvents = append(r.routeEvents, RouteEvent{Domain: domain, Mode: mode})
		if len(r.routeEvents) > 200 {
			r.routeEvents = r.routeEvents[len(r.routeEvents)-100:]
		}
	})

	r.appendLog("[core] runtime ready")
	writeCoreMarker(r.execDir, "core_runtime_start", "ready")
	return nil
}

func (r *coreRuntime) shutdown() {
	if r.externalTUN != nil {
		_ = r.externalTUN.Stop(nil)
	}
	_ = r.proxyServer.Stop()
	r.appendLog("[core] runtime stopped")
}

func (r *coreRuntime) reloadConfig() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if err := r.ruleManager.LoadConfig(); err != nil {
		return err
	}
	port := r.ruleManager.GetListenPort()
	if port == "" {
		port = "8080"
	}
	if err := r.proxyServer.SetListenAddr("127.0.0.1:" + port); err != nil {
		return err
	}
	r.proxyServer.SetRuleManager(r.ruleManager)
	r.proxyServer.UpdateCloudflareConfig(r.ruleManager.GetCloudflareConfig())
	r.proxyServer.SetCertGenerator(r.certManager)
	r.ruleManager.InitAutoRouter(r.proxyServer.GetDoHResolver())
	if r.externalTUN != nil {
		_ = r.externalTUN.RestartIfRunning(r.ruleManager.GetTUNConfig(), r.currentListenPort(), r.appendLog)
	}
	r.appendLog("[core] config reloaded")
	return nil
}

func (r *coreRuntime) reloadCertificate() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	cm, err := cert.InitCertManager(r.certPath)
	if err != nil {
		return err
	}
	r.certManager = cm
	r.proxyServer.SetCertGenerator(r.certManager)
	r.proxyServer.ClearCertCache()
	r.appendLog("[core] certificate reloaded")
	return nil
}

func (r *coreRuntime) setupLogger() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.SetOutput(newBestEffortMultiWriter(r.logBuffer, os.Stdout))
}

func (r *coreRuntime) appendLog(message string) {
	if r.logBuffer == nil {
		r.logBuffer = newRingLogWriter(500)
	}
	trimmed := strings.TrimSpace(message)
	if trimmed == "" {
		return
	}

	// Get buffer from pool to reduce allocation
	buf := logBufPool.Get().(*[]byte)
	*buf = (*buf)[:0] // Reset buffer

	// Write timestamp directly to buffer
	*buf = time.Now().AppendFormat(*buf, "2006/01/02 15:04:05.000000")
	*buf = append(*buf, ' ')
	*buf = append(*buf, trimmed...)
	if !strings.HasSuffix(trimmed, "\n") {
		*buf = append(*buf, '\n')
	}

	_, _ = r.logBuffer.Write(*buf)
	logBufPool.Put(buf) // Return to pool
}

func (r *coreRuntime) isLogCaptureEnabled() bool {
	r.logCaptureMu.RLock()
	defer r.logCaptureMu.RUnlock()
	return r.logCaptureEnabled
}

func (r *coreRuntime) startLogCapture() {
	r.logCaptureMu.Lock()
	r.logCaptureEnabled = true
	r.logCaptureMu.Unlock()
	if r.logBuffer != nil {
		r.logBuffer.Clear()
	}
	r.appendLog("[core] log capture started")
}

func (r *coreRuntime) stopLogCapture() {
	r.appendLog("[core] log capture stopping")
	r.logCaptureMu.Lock()
	r.logCaptureEnabled = false
	r.logCaptureMu.Unlock()
}

func (r *coreRuntime) recentLogs(limit int) string {
	if r.logBuffer == nil {
		return ""
	}
	return strings.Join(r.logBuffer.Snapshot(limit), "\n")
}

func (r *coreRuntime) clearLogs() {
	if r.logBuffer != nil {
		r.logBuffer.Clear()
	}
	r.appendLog("[core] logs cleared")
}

func (r *coreRuntime) startProxy() error {
	r.proxyOpMu.Lock()
	defer r.proxyOpMu.Unlock()

	originalPort := r.getListenPort()
	if originalPort == 0 {
		originalPort = 8080
	}
	availablePort, err := proxy.EnsurePortAvailable(originalPort, []string{"novaproxy", "usque"})
	if err != nil {
		availablePort = originalPort
	}
	if availablePort != originalPort {
		if err := r.setListenPort(availablePort); err != nil {
			return err
		}
	}
	if err := r.proxyServer.Start(); err != nil {
		return err
	}
	addr := r.proxyServer.GetListenAddr()
	if err := waitForListen(addr, 2*time.Second); err != nil {
		_ = r.proxyServer.Stop()
		return fmt.Errorf("proxy started but not listening on %s: %w", addr, err)
	}
	r.appendLog("[core] proxy started")
	return nil
}

func (r *coreRuntime) stopProxy() error {
	r.proxyOpMu.Lock()
	defer r.proxyOpMu.Unlock()
	var errs []error
	if err := r.proxyServer.Stop(); err != nil {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		return errorsJoin(errs...)
	}
	r.appendLog("[core] proxy stopped")
	return nil
}

func (r *coreRuntime) startTUN() (err error) {
	writeCoreMarker(r.execDir, "start_tun", "entered")
	r.setTUNStartState(true, nil)
	defer func() {
		if err != nil {
			writeCoreMarker(r.execDir, "start_tun", markerDetail("leaving with error: %v", err))
		} else {
			writeCoreMarker(r.execDir, "start_tun", "leaving without error")
		}
		r.setTUNStartState(false, err)
	}()

	if !isProcessElevated() {
		err = fmt.Errorf("TUN requires administrator privileges on Windows; please restart NovaProxy as administrator")
		writeCoreMarker(r.execDir, "start_tun", "not elevated")
		return err
	}
	if !r.proxyServer.IsRunning() {
		r.appendLog("[core] proxy not running, starting proxy before TUN")
		writeCoreMarker(r.execDir, "start_tun", "before startProxy")
		if err = r.startProxy(); err != nil {
			writeCoreMarker(r.execDir, "start_tun", markerDetail("startProxy failed: %v", err))
			return fmt.Errorf("start proxy before TUN: %w", err)
		}
		writeCoreMarker(r.execDir, "start_tun", "after startProxy")
	}
	if r.externalTUN == nil {
		err = fmt.Errorf("external mihomo manager is not initialized")
		writeCoreMarker(r.execDir, "start_tun", "external manager missing")
		return err
	}
	listenPort := r.currentListenPort()
	if listenPort == "" {
		err = fmt.Errorf("proxy listen port is empty")
		writeCoreMarker(r.execDir, "start_tun", "empty listen port")
		return err
	}
	writeCoreMarker(r.execDir, "start_tun", "before externalTUN.Start")
	if err = r.externalTUN.Start(r.ruleManager.GetTUNConfig(), listenPort, r.appendLog); err != nil {
		writeCoreMarker(r.execDir, "start_tun", markerDetail("externalTUN.Start failed: %v", err))
		return err
	}
	writeCoreMarker(r.execDir, "start_tun", "after externalTUN.Start")
	r.appendLog("[core] external mihomo tun started")
	return nil
}

func (r *coreRuntime) stopTUN() error {
	r.setTUNStartState(false, nil)
	if r.externalTUN == nil {
		return fmt.Errorf("external mihomo manager is not initialized")
	}
	if err := r.externalTUN.Stop(r.appendLog); err != nil {
		return err
	}
	r.appendLog("[core] external mihomo tun stopped")
	return nil
}

func (r *coreRuntime) getTUNStatus() proxy.TUNStatus {
	var status proxy.TUNStatus
	if r.externalTUN != nil {
		status = r.externalTUN.Status(r.ruleManager.GetTUNConfig())
	} else {
		status = proxy.TUNStatus{
			Supported: false,
			Enabled:   false,
			Running:   false,
			Message:   "External Mihomo TUN is not initialized",
		}
	}

	r.tunStateMu.RLock()
	starting := r.tunStarting
	startErr := strings.TrimSpace(r.tunStartErr)
	r.tunStateMu.RUnlock()

	if status.Running {
		status.Enabled = true
		return status
	}
	status.Enabled = false
	if starting {
		if strings.TrimSpace(status.Message) == "" ||
			strings.Contains(strings.ToLower(status.Message), "selected") ||
			strings.Contains(strings.ToLower(status.Message), "not running") {
			status.Message = "TUN startup in progress"
		}
		return status
	}
	if startErr != "" {
		status.Message = startErr
	}
	return status
}

func (r *coreRuntime) setTUNStartState(starting bool, err error) {
	r.tunStateMu.Lock()
	defer r.tunStateMu.Unlock()
	r.tunStarting = starting
	if starting {
		r.tunStartErr = ""
		return
	}
	if err != nil {
		r.tunStartErr = strings.TrimSpace(err.Error())
		return
	}
	r.tunStartErr = ""
}

func (r *coreRuntime) failTUNStart(err error) {
	r.setTUNStartState(false, err)
	if err != nil {
		r.appendLog("[core] TUN panic: " + err.Error())
		r.appendLog(string(debug.Stack()))
	}
}

func (r *coreRuntime) getListenAddr() string {
	return r.proxyServer.GetListenAddr()
}

func (r *coreRuntime) setListenAddr(addr string) error {
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
	if err := r.proxyServer.SetListenAddr(addr); err != nil {
		return err
	}
	r.ruleManager.SetListenHost(host)
	r.ruleManager.SetListenPort(portStr)
	return r.ruleManager.SaveConfig()
}

func (r *coreRuntime) getListenPort() int {
	addr := r.proxyServer.GetListenAddr()
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	var port int
	fmt.Sscanf(portStr, "%d", &port)
	return port
}

func (r *coreRuntime) currentListenPort() string {
	addr := strings.TrimSpace(r.proxyServer.GetListenAddr())
	if addr != "" {
		if _, port, err := net.SplitHostPort(addr); err == nil && strings.TrimSpace(port) != "" {
			return strings.TrimSpace(port)
		}
	}
	return strings.TrimSpace(r.ruleManager.GetListenPort())
}

func (r *coreRuntime) setListenPort(port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("invalid port number: %d", port)
	}
	host := r.ruleManager.GetListenHost()
	if host == "" {
		host = "127.0.0.1"
	}
	addr := fmt.Sprintf("%s:%d", host, port)
	if err := r.proxyServer.SetListenAddr(addr); err != nil {
		return err
	}
	r.ruleManager.SetListenPort(fmt.Sprintf("%d", port))
	return r.ruleManager.SaveConfig()
}

func (r *coreRuntime) setSOCKSAddr(addr string) error {
	if err := r.proxyServer.SetSOCKSAddr(addr); err != nil {
		return err
	}
	r.ruleManager.SetSocksAddr(addr)
	host, portStr, err := net.SplitHostPort(addr)
	if err == nil {
		r.ruleManager.SetSocksHost(host)
		r.ruleManager.SetSocksPort(portStr)
	}
	return r.ruleManager.SaveConfig()
}

func waitForListen(addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		lastErr = err
		time.Sleep(20 * time.Millisecond)
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("timeout")
	}
	return lastErr
}

func errorsJoin(errs ...error) error {
	var filtered []error
	for _, err := range errs {
		if err != nil {
			filtered = append(filtered, err)
		}
	}
	if len(filtered) == 0 {
		return nil
	}
	if len(filtered) == 1 {
		return filtered[0]
	}
	msgs := make([]string, 0, len(filtered))
	for _, err := range filtered {
		msgs = append(msgs, err.Error())
	}
	return errors.New(strings.Join(msgs, "; "))
}

func (r *coreRuntime) popRouteEvents() []RouteEvent {
	r.routeEventsMu.Lock()
	defer r.routeEventsMu.Unlock()
	if len(r.routeEvents) == 0 {
		return nil
	}
	events := r.routeEvents
	r.routeEvents = nil
	return events
}
