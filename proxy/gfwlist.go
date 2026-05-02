package proxy

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	defaultGFWListURL = "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/gfw.txt"
	gfwListCacheFile  = "gfwlist_cache.txt"
)

type GFWList struct {
	mu       sync.RWMutex
	domains  map[string]bool
	count    int
	lastLoad time.Time
}

func NewGFWList() *GFWList {
	return &GFWList{
		domains: make(map[string]bool),
	}
}

func (g *GFWList) LoadFromReader(r io.Reader) (int, error) {
	scanner := bufio.NewScanner(r)
	domains := make(map[string]bool, 5000)
	count := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") ||
			strings.HasPrefix(line, "Source:") || strings.HasPrefix(line, "---") {
			continue
		}
		domains[strings.ToLower(line)] = true
		count++
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}

	g.mu.Lock()
	g.domains = domains
	g.count = count
	g.lastLoad = time.Now()
	g.mu.Unlock()

	log.Printf("[GFWList] Loaded %d domains", count)
	return count, nil
}

func (g *GFWList) LoadFromURL(url string) (int, error) {
	if url == "" {
		url = defaultGFWListURL
	}
	log.Printf("[GFWList] Fetching from %s", url)
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return 0, fmt.Errorf("fetch GFWList: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("fetch GFWList: HTTP %d", resp.StatusCode)
	}
	return g.LoadFromReader(resp.Body)
}

func (g *GFWList) LoadFromFile(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	return g.LoadFromReader(f)
}

func (g *GFWList) SaveToFile(path string) error {
	g.mu.RLock()
	defer g.mu.RUnlock()

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}

	var sb strings.Builder
	for domain := range g.domains {
		sb.WriteString(domain)
		sb.WriteByte('\n')
	}
	return os.WriteFile(path, []byte(sb.String()), 0644)
}

// IsBlocked checks if the host (or any parent domain) is in the GFW list.
func (g *GFWList) IsBlocked(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return false
	}

	g.mu.RLock()
	defer g.mu.RUnlock()

	if len(g.domains) == 0 {
		return false
	}

	// Exact match
	if g.domains[host] {
		return true
	}

	// Suffix match: walk up the domain hierarchy
	parts := strings.Split(host, ".")
	for i := 1; i < len(parts); i++ {
		parent := strings.Join(parts[i:], ".")
		if g.domains[parent] {
			return true
		}
	}
	return false
}

func (g *GFWList) Count() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.count
}

func (g *GFWList) LastLoadTime() time.Time {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.lastLoad
}

// gfwListCachePath returns the path of the local cache file, relative to the rules file.
func gfwListCachePath(rulesPath string) string {
	return filepath.Join(filepath.Dir(rulesPath), gfwListCacheFile)
}
