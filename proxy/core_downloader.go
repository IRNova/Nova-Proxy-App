package proxy

import (
	"archive/zip"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type CoreType int

const (
	CoreV2Fly CoreType = iota
	CoreXray
	CoreSingBox
)

func (c CoreType) String() string {
	switch c {
	case CoreV2Fly:
		return "v2fly"
	case CoreXray:
		return "xray"
	case CoreSingBox:
		return "sing-box"
	}
	return "unknown"
}

type XrayRelease struct {
	TagName string `json:"tag_name"`
	Assets  []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
	} `json:"assets"`
}

type CoreManager struct {
	DataDir    string
	Cores      map[CoreType]string // core type -> binary path
	downloaded bool
}

func NewCoreManager(dataDir string) *CoreManager {
	return &CoreManager{
		DataDir: dataDir,
		Cores:   make(map[CoreType]string),
	}
}

// EnsureXrayCore downloads Xray-core if not present
func (cm *CoreManager) EnsureXrayCore() (string, error) {
	binDir := filepath.Join(cm.DataDir, "bin")
	os.MkdirAll(binDir, 0755)

	xrayPath := filepath.Join(binDir, "xray")
	if runtime.GOOS == "windows" {
		xrayPath += ".exe"
	}

	// Check if already downloaded
	if _, err := os.Stat(xrayPath); err == nil {
		cm.Cores[CoreXray] = xrayPath
		return xrayPath, nil
	}

	// Fetch latest release info
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get("https://api.github.com/repos/XTLS/Xray-core/releases/latest")
	if err != nil {
		return "", fmt.Errorf("failed to fetch latest xray release: %w", err)
	}
	defer resp.Body.Close()

	var release XrayRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return "", fmt.Errorf("failed to parse xray release: %w", err)
	}

	// Find the right asset for this platform
	assetName := cm.getAssetName(release.TagName)
	var downloadURL string
	for _, asset := range release.Assets {
		if asset.Name == assetName {
			downloadURL = asset.BrowserDownloadURL
			break
		}
	}
	if downloadURL == "" {
		return "", fmt.Errorf("no asset found for platform: %s", assetName)
	}

	// Download the zip
	zipPath := filepath.Join(binDir, assetName)
	if err := downloadFile(downloadURL, zipPath); err != nil {
		return "", fmt.Errorf("failed to download xray: %w", err)
	}

	// Extract
	if err := extractArchive(zipPath, binDir); err != nil {
		return "", fmt.Errorf("failed to extract xray: %w", err)
	}

	// Clean up zip
	os.Remove(zipPath)

	// Make executable on Unix
	if runtime.GOOS != "windows" {
		os.Chmod(xrayPath, 0755)
	}

	cm.Cores[CoreXray] = xrayPath
	return xrayPath, nil
}

func (cm *CoreManager) getAssetName(tag string) string {
	goos := runtime.GOOS
	arch := runtime.GOARCH

	switch goos {
	case "windows":
		switch arch {
		case "amd64":
			return fmt.Sprintf("Xray-windows-64.zip")
		case "arm64":
			return fmt.Sprintf("Xray-windows-arm64-v8a.zip")
		}
	case "linux":
		switch arch {
		case "amd64":
			return fmt.Sprintf("Xray-linux-64.zip")
		case "arm64":
			return fmt.Sprintf("Xray-linux-arm64-v8a.zip")
		case "arm":
			return fmt.Sprintf("Xray-linux-arm32-v7a.zip")
		}
	case "darwin":
		switch arch {
		case "amd64":
			return fmt.Sprintf("Xray-macos-64.zip")
		case "arm64":
			return fmt.Sprintf("Xray-macos-arm64-v8a.zip")
		}
	}
	return fmt.Sprintf("Xray-%s-%s.zip", goos, arch)
}

func downloadFile(url, dest string) error {
	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}

func extractArchive(src, dest string) error {
	if strings.HasSuffix(src, ".zip") {
		return extractZip(src, dest)
	}
	if strings.HasSuffix(src, ".tar.gz") || strings.HasSuffix(src, ".tgz") {
		return extractTarGz(src, dest)
	}
	return fmt.Errorf("unsupported archive format: %s", src)
}

func extractZip(src, dest string) error {
	r, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer r.Close()

	for _, f := range r.File {
		fpath := filepath.Join(dest, f.Name)
		if f.FileInfo().IsDir() {
			os.MkdirAll(fpath, 0755)
			continue
		}

		rc, err := f.Open()
		if err != nil {
			return err
		}

		outFile, err := os.Create(fpath)
		if err != nil {
			rc.Close()
			return err
		}

		_, err = io.Copy(outFile, rc)
		rc.Close()
		outFile.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func extractTarGz(src, dest string) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()

	gzr, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gzr.Close()

	// tar reader would go here - simplified for now
	// For sing-box which uses tar.gz
	return fmt.Errorf("tar.gz extraction not implemented yet")
}
