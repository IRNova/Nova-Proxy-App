package sysproxy

import (
	"fmt"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	proxySettingsKey = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`
	internetOptionRefresh         = 37
	internetOptionSettingsChanged = 39
)

var (
	wininetDLL             = syscall.NewLazyDLL("wininet.dll")
	internetSetOptionProc  = wininetDLL.NewProc("InternetSetOptionW")
	
	// Cache for system proxy status
	cachedStatus SystemProxyStatus
	lastCheck    time.Time
	cacheMu      sync.Mutex
)

type SystemProxyStatus struct {
	Enabled  bool
	Server   string
	Override string
}

func notifyProxyChange() error {
	if err := callInternetSetOption(internetOptionSettingsChanged); err != nil {
		return err
	}
	return callInternetSetOption(internetOptionRefresh)
}

func callInternetSetOption(option uintptr) error {
	ret, _, callErr := internetSetOptionProc.Call(0, option, 0, 0)
	if ret != 0 {
		return nil
	}
	if callErr != syscall.Errno(0) {
		return callErr
	}
	return fmt.Errorf("InternetSetOptionW failed for option %d", option)
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

	// بررسی ProxyEnable
	out, err := outputHiddenCommand("reg", "query", "HKCU\\"+proxySettingsKey, "/v", "ProxyEnable")
	if err == nil && len(out) > 0 {
		if strings.Contains(string(out), "0x1") {
			status.Enabled = true
		}
	}

	// بررسی ProxyServer
	out, err = outputHiddenCommand("reg", "query", "HKCU\\"+proxySettingsKey, "/v", "ProxyServer")
	if err == nil && len(out) > 0 {
		status.Server = parseRegValue(string(out))
	}

	// بررسی ProxyOverride
	out, err = outputHiddenCommand("reg", "query", "HKCU\\"+proxySettingsKey, "/v", "ProxyOverride")
	if err == nil && len(out) > 0 {
		status.Override = parseRegValue(string(out))
	}

	cacheMu.Lock()
	cachedStatus = status
	lastCheck = time.Now()
	cacheMu.Unlock()

	return status
}

func parseRegValue(output string) string {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 3 {
			return fields[len(fields)-1]
		}
	}
	return ""
}

func SetSystemProxy(enable bool, server string) error {
	enableVal := "0"
	if enable {
		enableVal = "1"
	}

	// Set ProxyEnable using reg command
	if err := runHiddenCommand("reg", "add", "HKCU\\"+proxySettingsKey, "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", enableVal, "/f"); err != nil {
		return fmt.Errorf("[sysproxy] failed to set ProxyEnable: %w", err)
	}

	// Set ProxyServer if enabling
	if enable {
		if server == "" {
			return fmt.Errorf("[sysproxy] server cannot be empty when enabling proxy")
		}
		if err := runHiddenCommand("reg", "add", "HKCU\\"+proxySettingsKey, "/v", "ProxyServer", "/t", "REG_SZ", "/d", server, "/f"); err != nil {
			return fmt.Errorf("[sysproxy] failed to set ProxyServer: %w", err)
		}

		// Set ProxyOverride
		override := "<local>"
		if err := runHiddenCommand("reg", "add", "HKCU\\"+proxySettingsKey, "/v", "ProxyOverride", "/t", "REG_SZ", "/d", override, "/f"); err != nil {
			return fmt.Errorf("[sysproxy] failed to set ProxyOverride: %w", err)
		}
	}

	cacheMu.Lock()
	lastCheck = time.Time{}
	cacheMu.Unlock()

	return notifyProxyChange()
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

func GetSystemProxyStatusSafe() (SystemProxyStatus, error) {
	status := GetSystemProxyStatus()
	return status, nil
}

var originalProxySettings *SystemProxyStatus

func SaveOriginalProxySettings() error {
	status := GetSystemProxyStatus()
	originalProxySettings = &status
	return nil
}

func SetOriginalProxySettings(status SystemProxyStatus) {
	copy := status
	originalProxySettings = &copy
}

func RestoreOriginalProxySettings() error {
	if originalProxySettings == nil {
		return nil
	}

	enableVal := "0"
	if originalProxySettings.Enabled {
		enableVal = "1"
	}

	// Restore ProxyEnable
	runHiddenCommand("reg", "add", "HKCU\\"+proxySettingsKey, "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", enableVal, "/f")

	// Restore ProxyServer if it was enabled
	if originalProxySettings.Enabled && originalProxySettings.Server != "" {
		runHiddenCommand("reg", "add", "HKCU\\"+proxySettingsKey, "/v", "ProxyServer", "/t", "REG_SZ", "/d", originalProxySettings.Server, "/f")
		if originalProxySettings.Override != "" {
			runHiddenCommand("reg", "add", "HKCU\\"+proxySettingsKey, "/v", "ProxyOverride", "/t", "REG_SZ", "/d", originalProxySettings.Override, "/f")
		}
	}

	cacheMu.Lock()
	lastCheck = time.Time{}
	cacheMu.Unlock()

	return notifyProxyChange()
}

// SetSystemProxyManual allows user to manually configure proxy via Windows settings
func SetSystemProxyManual() error {
	// Open Windows proxy settings interface
	return startHiddenCommand("cmd", "/c", "start", "ms-settings:network-proxy")
}
