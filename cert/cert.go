package cert

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
)

type CertManager struct {
	caCert  *x509.Certificate
	caKey   *rsa.PrivateKey
	certMu  sync.RWMutex
	caPath  string
	keyPath string

	// Cache for CA install status to avoid expensive PowerShell calls
	lastStatus CAInstallStatus
	lastCheck  time.Time
}

func NewCertManager(caPath, keyPath string) *CertManager {
	return &CertManager{
		caPath:  caPath,
		keyPath: keyPath,
	}
}

func (cm *CertManager) generateCAUnlocked() error {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate CA private key: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"NovaProxy"},
			CommonName:   "NovaProxy CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("failed to create CA certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return err
	}

	cm.caCert = cert
	cm.caKey = privateKey

	if err := cm.saveCA(); err != nil {
		return err
	}

	fmt.Println("[Cert] CA certificate generated successfully")
	return nil
}

func (cm *CertManager) GenerateCA() error {
	cm.certMu.Lock()
	defer cm.certMu.Unlock()
	return cm.generateCAUnlocked()
}

func (cm *CertManager) saveCA() error {
	caFile, err := os.Create(cm.caPath)
	if err != nil {
		return err
	}
	defer caFile.Close()

	if err := pem.Encode(caFile, &pem.Block{Type: "CERTIFICATE", Bytes: cm.caCert.Raw}); err != nil {
		return err
	}

	keyFile, err := os.Create(cm.keyPath)
	if err != nil {
		return err
	}
	defer keyFile.Close()

	keyBytes := x509.MarshalPKCS1PrivateKey(cm.caKey)
	if err := pem.Encode(keyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes}); err != nil {
		return err
	}

	return nil
}

func (cm *CertManager) LoadCA() error {
	cm.certMu.Lock()
	defer cm.certMu.Unlock()

	caData, err := os.ReadFile(cm.caPath)
	if err != nil {
		if os.IsNotExist(err) {
			return cm.generateCAUnlocked()
		}
		return err
	}

	block, _ := pem.Decode(caData)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}

	keyData, err := os.ReadFile(cm.keyPath)
	if err != nil {
		return err
	}

	keyBlock, _ := pem.Decode(keyData)
	key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return err
	}

	cm.caCert = cert
	cm.caKey = key

	return nil
}

func (cm *CertManager) GetCACertPath() string {
	return cm.caPath
}

func (cm *CertManager) GetCertPool() *x509.CertPool {
	pool := x509.NewCertPool()
	if cm.caCert != nil {
		pool.AddCert(cm.caCert)
	}
	return pool
}

func (cm *CertManager) GetCA() *x509.Certificate {
	cm.certMu.RLock()
	defer cm.certMu.RUnlock()
	return cm.caCert
}

func (cm *CertManager) GetCACert() *x509.Certificate {
	cm.certMu.RLock()
	defer cm.certMu.RUnlock()
	return cm.caCert
}

func (cm *CertManager) GetCAKey() interface{} {
	cm.certMu.RLock()
	defer cm.certMu.RUnlock()
	return cm.caKey
}

func (cm *CertManager) IsCAInstalled() bool {
	status := cm.GetCAInstallStatus()
	return status.Installed
}

type CAInstallStatus struct {
	Installed   bool
	Platform    string
	CertPath    string
	InstallHelp string
}

func (cm *CertManager) GetCAInstallStatus() CAInstallStatus {
	cm.certMu.Lock()
	if !cm.lastCheck.IsZero() && time.Since(cm.lastCheck) < 5*time.Minute {
		status := cm.lastStatus
		cm.certMu.Unlock()
		return status
	}
	cm.certMu.Unlock()

	platformHelp := map[string]string{
		"windows": "Install in Windows Trusted Root store via Settings > Security or run InstallCA",
		"darwin":  "Install in macOS Keychain via Keychain Access or run InstallCA",
		"linux":   "Install via system CA trust store (update-ca-certificates) or run InstallCA",
	}

	status := CAInstallStatus{
		CertPath:    cm.caPath,
		Platform:    runtime.GOOS,
		InstallHelp: platformHelp[runtime.GOOS],
	}
	if status.InstallHelp == "" {
		status.InstallHelp = "Manually install the CA certificate in your system trust store"
	}

	if cm.caCert == nil {
		if err := cm.LoadCA(); err != nil {
			return status
		}
	}
	if cm.caCert == nil {
		return status
	}

	// Use multi-platform IsCATrusted
	status.Installed = IsCATrusted(cm.caPath, DefaultCertName)

	// Fallback: Windows-only PowerShell check
	if !status.Installed && runtime.GOOS == "windows" {
		sum := sha1.Sum(cm.caCert.Raw)
		thumb := strings.ToUpper(hex.EncodeToString(sum[:]))

		psScript := fmt.Sprintf(`
			Add-Type -AssemblyName System.Security
			$thumb = '%s'
			$stores = @('Root', 'CA')
			$locations = @('CurrentUser', 'LocalMachine')
			foreach ($loc in $locations) {
				foreach ($name in $stores) {
					$store = New-Object System.Security.Cryptography.X509Certificates.X509Store($name, $loc)
					$store.Open('ReadOnly')
					$found = $store.Certificates.Find([System.Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint, $thumb, $false)
					$store.Close()
					if ($found.Count -gt 0) {
						Write-Output 'FOUND'
						exit 0
					}
				}
			}
		`, thumb)
		output, _ := outputHiddenCommand("powershell", "-NoProfile", "-Command", psScript)
		status.Installed = strings.Contains(strings.ToUpper(string(output)), "FOUND")
	}

	// Update cache
	cm.certMu.Lock()
	cm.lastStatus = status
	cm.lastCheck = time.Now()
	cm.certMu.Unlock()

	return status
}

func (cm *CertManager) InstallCA() error {
	if cm.caCert == nil || cm.caKey == nil {
		if err := cm.LoadCA(); err != nil {
			return err
		}
	}
	if cm.caPath == "" {
		return fmt.Errorf("CA certificate path is empty")
	}

	if certs, err := cm.GetInstalledCertificates(); err == nil {
		for _, c := range certs {
			_ = cm.UninstallCertificate(c.Token)
		}
	}

	// Multi-platform CA installation
	if InstallCATrust(cm.caPath, DefaultCertName) {
		cm.invalidateInstallStatusCache()
		fmt.Printf("[Cert] CA certificate installed successfully on %s\n", runtime.GOOS)
		return nil
	}

	// Fallback to Windows-only certutil for backward compatibility
	if runtime.GOOS == "windows" {
		err := runHiddenCommand("certutil", "-user", "-addstore", "root", cm.caPath)
		if err != nil {
			return fmt.Errorf("failed to install CA certificate: %w", err)
		}

		cm.invalidateInstallStatusCache()
		fmt.Println("[Cert] CA certificate installed successfully to CurrentUser Root store (certutil fallback)")
		return nil
	}

	return fmt.Errorf("failed to install CA certificate on %s", runtime.GOOS)
}

type InstalledCert struct {
	Subject       string `json:"subject"`
	Thumbprint    string `json:"thumbprint"`
	NotAfter      string `json:"notAfter"`
	StoreName     string `json:"storeName"`
	StoreLocation string `json:"storeLocation"`
	Token         string `json:"token"`
}

func (cm *CertManager) GetInstalledCertificates() ([]InstalledCert, error) {
	var caThumbprint string
	cm.certMu.RLock()
	if cm.caCert != nil {
		sum := sha1.Sum(cm.caCert.Raw)
		caThumbprint = strings.ToUpper(hex.EncodeToString(sum[:]))
	}
	cm.certMu.RUnlock()

	psScript := `
$caThumbprint = '` + caThumbprint + `'
$stores = @(
  @{ Location = 'CurrentUser'; Name = 'Root' },
  @{ Location = 'CurrentUser'; Name = 'CA' },
  @{ Location = 'LocalMachine'; Name = 'Root' },
  @{ Location = 'LocalMachine'; Name = 'CA' }
)
$result = @()
foreach ($spec in $stores) {
  $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($spec.Name, $spec.Location)
  try {
    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
    foreach ($cert in $store.Certificates) {
      if ($cert.Subject -match 'NovaProxy' -or $cert.Issuer -match 'NovaProxy' -or ($caThumbprint -ne '' -and $cert.Thumbprint -eq $caThumbprint)) {
        $result += [PSCustomObject]@{
          subject = $cert.Subject
          thumbprint = $cert.Thumbprint
          notAfter = $cert.NotAfter.ToString('yyyy-MM-dd HH:mm:ss')
          storeName = $spec.Name
          storeLocation = $spec.Location
          token = "$($spec.Location)|$($spec.Name)|$($cert.Thumbprint)"
        }
      }
    }
  } finally {
    $store.Close()
  }
}
$result | ConvertTo-Json -Compress
`
	output, err := outputHiddenCommand("powershell", "-NoProfile", "-Command", psScript)
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate certificate stores: %w", err)
	}

	text := strings.TrimSpace(string(output))
	if text == "" {
		return []InstalledCert{}, nil
	}

	var certs []InstalledCert
	if strings.HasPrefix(text, "[") {
		if err := json.Unmarshal(output, &certs); err != nil {
			return nil, fmt.Errorf("failed to parse installed certificates: %w", err)
		}
		return certs, nil
	}

	var single InstalledCert
	if err := json.Unmarshal(output, &single); err != nil {
		return nil, fmt.Errorf("failed to parse installed certificate: %w", err)
	}
	return []InstalledCert{single}, nil
}

var sha1ThumbprintPattern = regexp.MustCompile(`(?i)[A-F0-9]{40}`)

func parseCertutilStoreOutput(output []byte, storeLocation, storeName string) []InstalledCert {
	scanner := bufio.NewScanner(bytes.NewReader(output))
	var blocks [][]string
	var current []string

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.Contains(line, "====") {
			if len(current) > 0 {
				blocks = append(blocks, current)
			}
			current = []string{line}
			continue
		}
		if len(current) > 0 {
			current = append(current, line)
		}
	}
	if len(current) > 0 {
		blocks = append(blocks, current)
	}

	var certs []InstalledCert
	for _, block := range blocks {
		joined := strings.Join(block, "\n")
		if !strings.Contains(strings.ToLower(joined), "novaproxy") {
			continue
		}

		var subject string
		var notAfter string
		var thumbprint string

		for _, line := range block {
			lower := strings.ToLower(line)
			if subject == "" && strings.Contains(lower, "novaproxy") {
				if idx := strings.Index(line, ":"); idx >= 0 && idx+1 < len(line) {
					subject = strings.TrimSpace(line[idx+1:])
				}
			}
			if notAfter == "" && strings.Contains(lower, "notafter:") {
				if idx := strings.Index(line, ":"); idx >= 0 && idx+1 < len(line) {
					notAfter = strings.TrimSpace(line[idx+1:])
				}
			}
			if thumbprint == "" {
				if match := sha1ThumbprintPattern.FindString(line); match != "" {
					thumbprint = strings.ToUpper(match)
				}
			}
		}

		if thumbprint == "" {
			continue
		}
		if subject == "" {
			subject = "NovaProxy CA"
		}

		certs = append(certs, InstalledCert{
			Subject:       subject,
			Thumbprint:    thumbprint,
			NotAfter:      notAfter,
			StoreName:     storeName,
			StoreLocation: storeLocation,
			Token:         storeLocation + "|" + storeName + "|" + thumbprint,
		})
	}

	return certs
}

func (cm *CertManager) UninstallCertificate(thumbprint string) error {
	if thumbprint == "" {
		return fmt.Errorf("thumbprint is empty")
	}

	storeLocation := "CurrentUser"
	storeName := "Root"
	certThumbprint := thumbprint

	if parts := strings.SplitN(thumbprint, "|", 3); len(parts) == 3 {
		storeLocation = parts[0]
		storeName = parts[1]
		certThumbprint = parts[2]
	}

	args := []string{}
	if strings.EqualFold(storeLocation, "CurrentUser") {
		args = append(args, "-user")
	}
	args = append(args, "-delstore", storeName, certThumbprint)

	if strings.EqualFold(storeLocation, "LocalMachine") {
		if err := runElevatedCommand("certutil", args...); err != nil {
			return err
		}
		cm.invalidateInstallStatusCache()
		return nil
	}

	if err := runHiddenCommand("certutil", args...); err != nil {
		return err
	}
	cm.invalidateInstallStatusCache()
	return nil
}

func (cm *CertManager) invalidateInstallStatusCache() {
	cm.certMu.Lock()
	cm.lastCheck = time.Time{}
	cm.certMu.Unlock()
}

func (cm *CertManager) OpenCertDir() error {
	dir := filepath.Dir(cm.caPath)
	return startVisibleCommand("explorer.exe", dir)
}
func (cm *CertManager) OpenCAFile() error {
	return startVisibleCommand("explorer.exe", "/select,"+cm.caPath)
}

func (cm *CertManager) GetCACertPEM() string {
	cm.certMu.RLock()
	defer cm.certMu.RUnlock()
	if cm.caCert == nil {
		return ""
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cm.caCert.Raw}))
}

func (cm *CertManager) RegenerateCA() error {
	// 1. Try to clean up existing certificates from system store
	certs, err := cm.GetInstalledCertificates()
	if err == nil {
		for _, c := range certs {
			fmt.Printf("[Cert] Cleaning up old cert: %s\n", c.Thumbprint)
			_ = cm.UninstallCertificate(c.Token)
		}
	}

	// 2. Generate new CA
	cm.certMu.Lock()
	if err := cm.generateCAUnlocked(); err != nil {
		cm.certMu.Unlock()
		return err
	}
	cm.certMu.Unlock()

	fmt.Println("[Cert] CA certificate regenerated successfully")

	// 3. Install the new one
	return cm.InstallCA()
}

func (cm *CertManager) ExportCert() ([]byte, error) {
	cm.certMu.RLock()
	defer cm.certMu.RUnlock()
	if cm.caCert == nil {
		return nil, fmt.Errorf("no CA certificate available")
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cm.caCert.Raw}), nil
}

func InitCertManager(certDir string) (*CertManager, error) {
	return InitCertManagerWithFallback(certDir, "")
}

func InitCertManagerWithFallback(certDir, fallbackCADir string) (*CertManager, error) {
	os.MkdirAll(certDir, 0755)

	targetCACert := filepath.Join(certDir, "ca.crt")
	targetCAKey := filepath.Join(certDir, "ca.key")

	if fallbackCADir != "" {
		fallbackCACert := filepath.Join(fallbackCADir, "ca.crt")
		fallbackCAKey := filepath.Join(fallbackCADir, "ca.key")

		if fileExists(fallbackCACert) && fileExists(fallbackCAKey) {
			shouldCopy := false
			reason := ""

			if !fileExists(targetCACert) || !fileExists(targetCAKey) {
				shouldCopy = true
				reason = "no existing CA found"
			} else {
				fallbackCN := getCertCN(fallbackCACert)
				targetCN := getCertCN(targetCACert)

				if fallbackCN != "" && targetCN != "" && fallbackCN != targetCN {
					if strings.Contains(strings.ToLower(fallbackCN), "mhr-gsa") {
						shouldCopy = true
						reason = fmt.Sprintf("fallback CA (%s) is mhr-gsa which differs from existing CA (%s)", fallbackCN, targetCN)
					}
				}
			}

			if shouldCopy {
				fmt.Println("[Cert]", reason, "- copying fallback CA from", fallbackCADir, "to", certDir)
				if err := copyFile(fallbackCACert, targetCACert); err != nil {
					fmt.Println("[Cert] Warning: failed to copy ca.crt:", err)
				}
				if err := copyFile(fallbackCAKey, targetCAKey); err != nil {
					fmt.Println("[Cert] Warning: failed to copy ca.key:", err)
				}
			} else {
				fmt.Println("[Cert] Using existing CA in", certDir)
			}
		}
	}

	cm := NewCertManager(targetCACert, targetCAKey)

	if err := cm.LoadCA(); err != nil {
		_ = os.Remove(cm.caPath)
		_ = os.Remove(cm.keyPath)
		if genErr := cm.GenerateCA(); genErr != nil {
			return nil, fmt.Errorf("load existing CA failed: %v; regenerate failed: %w", err, genErr)
		}
	}

	return cm, nil
}

func getCertCN(certPath string) string {
	data, err := os.ReadFile(certPath)
	if err != nil {
		return ""
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return ""
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return ""
	}
	return cert.Subject.CommonName
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0644)
}
