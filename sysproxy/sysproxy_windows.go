package sysproxy

import (
	"fmt"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/windows/registry"
)

const (
	proxySettingsKey         = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`
	internetOptionSettingsChanged = 39
)

var (
	wininetDLL             = syscall.NewLazyDLL("wininet.dll")
	internetSetOptionProc  = wininetDLL.NewProc("InternetSetOptionW")

	cachedStatus SystemProxyStatus
	lastCheck    time.Time
	cacheMu      sync.Mutex
)

type SystemProxyStatus struct {
	Enabled  bool
	Server   string
	Override string
}

func GetSystemProxyStatus() SystemProxyStatus {
	cacheMu.Lock()
	if !lastCheck.IsZero() && time.Since(lastCheck) < 2*time.Second {
		status := cachedStatus
		cacheMu.Unlock()
		return status
	}
	cacheMu.Unlock()

	status := SystemProxyStatus{}
	k, err := registry.OpenKey(registry.CURRENT_USER, proxySettingsKey, registry.QUERY_VALUE)
	if err != nil {
		return status
	}
	defer k.Close()

	enableVal, _, err := k.GetIntegerValue("ProxyEnable")
	if err == nil && enableVal == 1 {
		status.Enabled = true
	}

	serverVal, _, err := k.GetStringValue("ProxyServer")
	if err == nil {
		status.Server = strings.TrimSpace(serverVal)
	}

	overrideVal, _, err := k.GetStringValue("ProxyOverride")
	if err == nil {
		status.Override = strings.TrimSpace(overrideVal)
	}

	cacheMu.Lock()
	cachedStatus = status
	lastCheck = time.Now()
	cacheMu.Unlock()

	return status
}

func SetSystemProxy(enable bool, server string) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, proxySettingsKey, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("[sysproxy] failed to open registry key: %w", err)
	}
	defer k.Close()

	enableVal := uint64(0)
	if enable {
		enableVal = 1
	}

	if err := k.SetDWordValue("ProxyEnable", uint32(enableVal)); err != nil {
		return fmt.Errorf("[sysproxy] failed to set ProxyEnable: %w", err)
	}

	if enable {
		if server == "" {
			return fmt.Errorf("[sysproxy] server cannot be empty when enabling proxy")
		}
		if err := k.SetStringValue("ProxyServer", server); err != nil {
			return fmt.Errorf("[sysproxy] failed to set ProxyServer: %w", err)
		}
		if err := k.SetStringValue("ProxyOverride", "<local>"); err != nil {
			return fmt.Errorf("[sysproxy] failed to set ProxyOverride: %w", err)
		}
	} else {
		// Always clear ProxyServer when disabling to prevent stale values
		_ = k.DeleteValue("ProxyServer")
		_ = k.DeleteValue("ProxyOverride")
	}

	cacheMu.Lock()
	lastCheck = time.Time{}
	cacheMu.Unlock()

	// Notify WinINET apps (IE, Edge, etc.) that proxy changed — without refresh
	// so it doesn't cause network disruption. Browsers will pick up the new settings.
	internetSetOptionProc.Call(0, internetOptionSettingsChanged, 0, 0)

	return nil
}

func EnableSystemProxy(port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("[sysproxy] invalid port: %d", port)
	}
	server := fmt.Sprintf("127.0.0.1:%d", port)
	return SetSystemProxy(true, server)
}

func DisableSystemProxy() error {
	return SetSystemProxy(false, "")
}

var (
	originalProxySettings   *SystemProxyStatus
	originalProxySettingsMu sync.Mutex
)

func SaveOriginalProxySettings() error {
	status := GetSystemProxyStatus()
	originalProxySettingsMu.Lock()
	originalProxySettings = &status
	originalProxySettingsMu.Unlock()
	return nil
}

func SetOriginalProxySettings(status SystemProxyStatus) {
	copy := status
	originalProxySettingsMu.Lock()
	originalProxySettings = &copy
	originalProxySettingsMu.Unlock()
}

func RestoreOriginalProxySettings() error {
	originalProxySettingsMu.Lock()
	settings := originalProxySettings
	originalProxySettingsMu.Unlock()

	if settings == nil {
		// No original settings saved - force disable everything
		return SetSystemProxy(false, "")
	}

	return SetSystemProxy(settings.Enabled, settings.Server)
}

func SetSystemProxyManual() error {
	return startHiddenCommand("cmd", "/c", "start", "ms-settings:network-proxy")
}
