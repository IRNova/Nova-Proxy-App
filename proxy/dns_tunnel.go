package proxy

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
)

// DNSTunnel wraps MasterDnsVPN as a subprocess
type DNSTunnel struct {
	Domain      string   `json:"domain"`
	EncKey      string   `json:"enc_key"`
	Resolvers   []string `json:"resolvers"`
	SOCKS5Port  int      `json:"socks5_port"`
	EncMethod   int      `json:"enc_method"` // 0=None, 1=XOR, 2=ChaCha20, 3-5=AES-GCM
	Duplication int      `json:"duplication"`

	cmd        *exec.Cmd
	configPath string
	started    bool
}

func NewDNSTunnel(domain, encKey string, resolvers []string) *DNSTunnel {
	if len(resolvers) == 0 {
		resolvers = []string{
			"8.8.8.8",
			"1.1.1.1",
			"9.9.9.9",
			"208.67.222.222",
		}
	}
	return &DNSTunnel{
		Domain:      domain,
		EncKey:      encKey,
		Resolvers:   resolvers,
		SOCKS5Port:  18000,
		EncMethod:   1, // XOR (lightweight)
		Duplication: 2,
	}
}

func (d *DNSTunnel) Start() error {
	if d.started {
		return fmt.Errorf("dns tunnel already running")
	}

	// Find the MasterDnsVPN client binary
	binPath := d.findBinary()
	if binPath == "" {
		return fmt.Errorf("MasterDnsVPN client binary not found")
	}

	// Create config
	tmpDir := os.TempDir()
	d.configPath = filepath.Join(tmpDir, "novaproxy_dns_client.toml")

	if err := d.writeConfig(); err != nil {
		return fmt.Errorf("write dns config: %w", err)
	}

	// Create resolvers file
	resolversPath := filepath.Join(tmpDir, "novaproxy_dns_resolvers.txt")
	if err := d.writeResolvers(resolversPath); err != nil {
		return fmt.Errorf("write resolvers: %w", err)
	}

	// Start process
	d.cmd = exec.Command(binPath, "-config", d.configPath)
	d.cmd.Stdout = os.Stdout
	d.cmd.Stderr = os.Stderr

	if err := d.cmd.Start(); err != nil {
		return fmt.Errorf("start dns tunnel: %w", err)
	}

	d.started = true
	time.Sleep(1 * time.Second) // wait for bootstrap
	return nil
}

func (d *DNSTunnel) Stop() {
	if d.cmd != nil && d.cmd.Process != nil {
		d.cmd.Process.Kill()
		d.cmd.Wait()
		d.cmd = nil
	}
	d.started = false
}

func (d *DNSTunnel) IsRunning() bool {
	return d.started && d.cmd != nil && d.cmd.Process != nil
}

func (d *DNSTunnel) SOCKS5Addr() string {
	return fmt.Sprintf("127.0.0.1:%d", d.SOCKS5Port)
}

func (d *DNSTunnel) findBinary() string {
	// Search paths
	searchPaths := []string{
		"dns-tunnel/cmd/client",
		"dns-tunnel", // submodule root
		".",
	}

	binName := "MasterDnsVPN_Client"
	if runtime.GOOS == "windows" {
		binName += ".exe"
	}

	for _, p := range searchPaths {
		candidate := filepath.Join(p, binName)
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
		// Check parent directory
		parent := filepath.Join("..", p, binName)
		if _, err := os.Stat(parent); err == nil {
			return parent
		}
	}

	// Try to build from source
	sourceDir := "dns-tunnel"
	if _, err := os.Stat(filepath.Join(sourceDir, "go.mod")); err == nil {
		output := filepath.Join(os.TempDir(), binName)
		cmd := exec.Command("go", "build", "-o", output, "./cmd/client")
		cmd.Dir = sourceDir
		if err := cmd.Run(); err == nil {
			return output
		}
	}

	return ""
}

func (d *DNSTunnel) writeConfig() error {
	config := fmt.Sprintf(`PROTOCOL_TYPE = "SOCKS5"
DOMAINS = ["%s"]
DATA_ENCRYPTION_METHOD = %d
ENCRYPTION_KEY = "%s"
LISTEN_IP = "127.0.0.1"
LISTEN_PORT = %d
SOCKS5_AUTH = false
PACKET_DUPLICATION_COUNT = %d
SETUP_PACKET_DUPLICATION_COUNT = %d
BASE_ENCODE_DATA = false
UPLOAD_COMPRESSION_TYPE = 1
DOWNLOAD_COMPRESSION_TYPE = 1
COMPRESSION_MIN_SIZE = 120
RESOLVER_BALANCING_STRATEGY = 2
RECHECK_INACTIVE_SERVERS_ENABLED = true
`,
		d.Domain,
		d.EncMethod,
		d.EncKey,
		d.SOCKS5Port,
		d.Duplication,
		d.Duplication,
	)

	return os.WriteFile(d.configPath, []byte(config), 0644)
}

func (d *DNSTunnel) writeResolvers(path string) error {
	var data string
	for _, r := range d.Resolvers {
		data += r + "\n"
	}
	return os.WriteFile(path, []byte(data), 0644)
}
