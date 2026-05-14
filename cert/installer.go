package cert

import (
	"bytes"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

const DefaultCertName = "NovaProxy GSA"

// InstallCATrust installs the CA certificate into the system trust store.
// Supports Windows, macOS, Linux, and Firefox.
func InstallCATrust(certPath, certName string) bool {
	if _, err := os.Stat(certPath); err != nil {
		fmt.Printf("[Cert] Certificate file not found: %s\n", certPath)
		return false
	}
	switch runtime.GOOS {
	case "windows":
		ok := installCAWindows(certPath)
		installCAFirefox(certPath, certName)
		return ok
	case "darwin":
		ok := installCAMacOS(certPath)
		installCAFirefox(certPath, certName)
		return ok
	case "linux":
		ok := installCALinux(certPath, certName)
		installCAFirefox(certPath, certName)
		return ok
	default:
		fmt.Printf("[Cert] Unsupported platform: %s\n", runtime.GOOS)
		return false
	}
}

// UninstallCATrust removes the CA certificate from the system trust store.
func UninstallCATrust(certPath, certName string) bool {
	switch runtime.GOOS {
	case "windows":
		ok := uninstallCAWindows(certPath, certName)
		uninstallCAFirefox(certName)
		return ok
	case "darwin":
		ok := uninstallCAMacOS(certName)
		uninstallCAFirefox(certName)
		return ok
	case "linux":
		ok := uninstallCALinux(certPath, certName)
		uninstallCAFirefox(certName)
		return ok
	default:
		fmt.Printf("[Cert] Unsupported platform: %s\n", runtime.GOOS)
		return false
	}
}

// IsCATrusted checks if the CA certificate is installed in the system trust store.
func IsCATrusted(certPath, certName string) bool {
	switch runtime.GOOS {
	case "windows":
		return isTrustedCAWindows(certPath)
	case "darwin":
		return isTrustedCAMacOS(certName)
	case "linux":
		return isTrustedCALinux(certPath, certName)
	default:
		return false
	}
}

// --- Windows ---

func installCAWindows(certPath string) bool {
	if out, err := runCmd([]string{"certutil", "-addstore", "-user", "Root", certPath}, true); err == nil {
		fmt.Printf("[Cert] Certificate installed in Windows user Trusted Root store.\n")
		_ = out
		return true
	}
	if out, err := runCmd([]string{"certutil", "-addstore", "Root", certPath}, true); err == nil {
		fmt.Printf("[Cert] Certificate installed in Windows system Trusted Root store.\n")
		_ = out
		return true
	}
	ps := "Import-Certificate -FilePath '" + certPath + "' -CertStoreLocation Cert:\\CurrentUser\\Root"
	if out, err := runCmd([]string{"powershell", "-NoProfile", "-Command", ps}, true); err == nil {
		fmt.Printf("[Cert] Certificate installed via PowerShell.\n")
		_ = out
		return true
	}
	return false
}

func uninstallCAWindows(certPath, certName string) bool {
	thumb := certThumbprint(certPath)
	target := certName
	if thumb != "" {
		target = thumb
	}
	if out, err := runCmd([]string{"certutil", "-delstore", "-user", "Root", target}, true); err == nil {
		fmt.Printf("[Cert] Certificate removed from Windows user Trusted Root store.\n")
		_ = out
		return true
	}
	if out, err := runCmd([]string{"certutil", "-delstore", "Root", target}, true); err == nil {
		fmt.Printf("[Cert] Certificate removed from Windows system Trusted Root store.\n")
		_ = out
		return true
	}
	return false
}

func isTrustedCAWindows(certPath string) bool {
	out, err := runCmd([]string{"certutil", "-user", "-store", "Root"}, true)
	if err != nil {
		return false
	}
	thumb := certThumbprint(certPath)
	if thumb == "" {
		return false
	}
	return strings.Contains(strings.ToUpper(string(out)), thumb)
}

// --- macOS ---

func installCAMacOS(certPath string) bool {
	login := filepath.Join(os.Getenv("HOME"), "Library/Keychains/login.keychain-db")
	if out, err := runCmd([]string{"security", "add-trusted-cert", "-d", "-r", "trustRoot", "-k", login, certPath}, true); err == nil {
		fmt.Printf("[Cert] Certificate installed in macOS login keychain.\n")
		_ = out
		return true
	}
	if out, err := runCmd([]string{"sudo", "security", "add-trusted-cert", "-d", "-r", "trustRoot", "-k", "/Library/Keychains/System.keychain", certPath}, true); err == nil {
		fmt.Printf("[Cert] Certificate installed in macOS system keychain.\n")
		_ = out
		return true
	}
	return false
}

func uninstallCAMacOS(certName string) bool {
	login := filepath.Join(os.Getenv("HOME"), "Library/Keychains/login.keychain-db")
	if out, err := runCmd([]string{"security", "delete-certificate", "-c", certName, login}, true); err == nil {
		fmt.Printf("[Cert] Certificate removed from macOS login keychain.\n")
		_ = out
		return true
	}
	if out, err := runCmd([]string{"sudo", "security", "delete-certificate", "-c", certName, "/Library/Keychains/System.keychain"}, true); err == nil {
		fmt.Printf("[Cert] Certificate removed from macOS system keychain.\n")
		_ = out
		return true
	}
	return false
}

func isTrustedCAMacOS(certName string) bool {
	out, err := runCmd([]string{"security", "find-certificate", "-a", "-c", certName}, true)
	return err == nil && len(bytes.TrimSpace(out)) > 0
}

// --- Linux ---

func installCALinux(certPath, certName string) bool {
	distro := detectLinuxDistro()
	fmt.Printf("[Cert] Detected Linux distro family: %s\n", distro)

	switch distro {
	case "debian":
		dest := "/usr/local/share/ca-certificates/" + strings.ReplaceAll(certName, " ", "_") + ".crt"
		if out, err := runCmd([]string{"cp", certPath, dest}, true); err == nil {
			_, _ = runCmd([]string{"update-ca-certificates"}, true)
			fmt.Printf("[Cert] Certificate installed via update-ca-certificates.\n")
			_ = out
			return true
		}
	case "rhel":
		dest := "/etc/pki/ca-trust/source/anchors/" + strings.ReplaceAll(certName, " ", "_") + ".crt"
		if out, err := runCmd([]string{"cp", certPath, dest}, true); err == nil {
			_, _ = runCmd([]string{"update-ca-trust", "extract"}, true)
			fmt.Printf("[Cert] Certificate installed via update-ca-trust.\n")
			_ = out
			return true
		}
	case "arch":
		dest := "/etc/ca-certificates/trust-source/anchors/" + strings.ReplaceAll(certName, " ", "_") + ".crt"
		if out, err := runCmd([]string{"cp", certPath, dest}, true); err == nil {
			_, _ = runCmd([]string{"trust", "extract-compat"}, true)
			fmt.Printf("[Cert] Certificate installed via trust extract-compat.\n")
			_ = out
			return true
		}
	}
	fmt.Printf("[Cert] Unknown Linux distro. Manually install %s as a trusted root CA.\n", certPath)
	return false
}

func uninstallCALinux(certPath, certName string) bool {
	distro := detectLinuxDistro()
	fmt.Printf("[Cert] Detected Linux distro family: %s\n", distro)

	switch distro {
	case "debian":
		dest := "/usr/local/share/ca-certificates/" + strings.ReplaceAll(certName, " ", "_") + ".crt"
		_ = os.Remove(dest)
		_, _ = runCmd([]string{"update-ca-certificates"}, true)
		fmt.Printf("[Cert] Certificate removed via update-ca-certificates.\n")
		return true
	case "rhel":
		dest := "/etc/pki/ca-trust/source/anchors/" + strings.ReplaceAll(certName, " ", "_") + ".crt"
		_ = os.Remove(dest)
		_, _ = runCmd([]string{"update-ca-trust", "extract"}, true)
		fmt.Printf("[Cert] Certificate removed via update-ca-trust.\n")
		return true
	case "arch":
		dest := "/etc/ca-certificates/trust-source/anchors/" + strings.ReplaceAll(certName, " ", "_") + ".crt"
		_ = os.Remove(dest)
		_, _ = runCmd([]string{"trust", "extract-compat"}, true)
		fmt.Printf("[Cert] Certificate removed via trust extract-compat.\n")
		return true
	}
	fmt.Printf("[Cert] Unknown Linux distro. Manually remove %s from trusted CAs.\n", certName)
	return false
}

func isTrustedCALinux(certPath, certName string) bool {
	target := strings.ReplaceAll(certName, " ", "_") + ".crt"
	paths := []string{
		"/usr/local/share/ca-certificates/" + target,
		"/etc/pki/ca-trust/source/anchors/" + target,
		"/etc/ca-certificates/trust-source/anchors/" + target,
	}
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}

func detectLinuxDistro() string {
	if fileExists("/etc/debian_version") || fileExists("/etc/ubuntu") {
		return "debian"
	}
	if fileExists("/etc/redhat-release") || fileExists("/etc/fedora-release") {
		return "rhel"
	}
	if fileExists("/etc/arch-release") {
		return "arch"
	}
	return "unknown"
}

// --- Firefox (cross-platform) ---

func installCAFirefox(certPath, certName string) {
	if _, err := exec.LookPath("certutil"); err != nil {
		return
	}
	profiles := firefoxProfiles()
	for _, profile := range profiles {
		db := "sql:" + profile
		if !fileExists(filepath.Join(profile, "cert9.db")) {
			db = "dbm:" + profile
		}
		_, _ = runCmd([]string{"certutil", "-D", "-n", certName, "-d", db}, false)
		_, _ = runCmd([]string{"certutil", "-A", "-n", certName, "-t", "CT,,", "-i", certPath, "-d", db}, true)
	}
}

func uninstallCAFirefox(certName string) {
	if _, err := exec.LookPath("certutil"); err != nil {
		return
	}
	profiles := firefoxProfiles()
	for _, profile := range profiles {
		db := "sql:" + profile
		if !fileExists(filepath.Join(profile, "cert9.db")) {
			db = "dbm:" + profile
		}
		_, _ = runCmd([]string{"certutil", "-D", "-n", certName, "-d", db}, false)
	}
}

func firefoxProfiles() []string {
	var out []string
	switch runtime.GOOS {
	case "windows":
		appdata := os.Getenv("APPDATA")
		if appdata != "" {
			out = append(out, globFiles(filepath.Join(appdata, "Mozilla", "Firefox", "Profiles", "*"))...)
		}
	case "darwin":
		out = append(out, globFiles(filepath.Join(os.Getenv("HOME"), "Library", "Application Support", "Firefox", "Profiles", "*"))...)
	default:
		out = append(out, globFiles(filepath.Join(os.Getenv("HOME"), ".mozilla", "firefox", "*.default*"))...)
		out = append(out, globFiles(filepath.Join(os.Getenv("HOME"), ".mozilla", "firefox", "*.release*"))...)
	}
	return out
}

// --- Utilities ---

func runCmd(cmd []string, check bool) ([]byte, error) {
	c := exec.Command(cmd[0], cmd[1:]...)
	var buf bytes.Buffer
	c.Stdout = &buf
	c.Stderr = &buf
	err := c.Run()
	if err != nil && check {
		return buf.Bytes(), err
	}
	return buf.Bytes(), nil
}

func certThumbprint(certPath string) string {
	raw, err := os.ReadFile(certPath)
	if err != nil {
		return ""
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return ""
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return ""
	}
	sum := sha1.Sum(cert.Raw)
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

func globFiles(pattern string) []string {
	m, _ := filepath.Glob(pattern)
	return m
}

