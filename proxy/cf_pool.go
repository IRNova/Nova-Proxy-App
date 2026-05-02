package proxy

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

type IPStats struct {
	IP            string `json:"ip"`
	Latency       string `json:"latency"`
	Failures      int    `json:"failures"`
	LastCheck     string `json:"last_check"`
	latencyVal    time.Duration
	lastCheckTime time.Time
}

type CloudflarePool struct {
	allIPs    map[string]*IPStats // Keep track of stats for all IPs
	activeIPs []*IPStats          // IPs that are considered healthy, sorted by latency
	mu        sync.RWMutex
	stopChan  chan struct{}
	running   bool
}

func NewCloudflarePool(ips []string) *CloudflarePool {
	p := &CloudflarePool{
		allIPs:    make(map[string]*IPStats),
		activeIPs: make([]*IPStats, 0),
		stopChan:  make(chan struct{}),
	}
	p.UpdateIPs(ips)
	return p
}

func (p *CloudflarePool) Start() {
	p.mu.Lock()
	if p.running {
		p.mu.Unlock()
		return
	}
	p.running = true
	p.stopChan = make(chan struct{})
	p.mu.Unlock()

	go p.healthCheckLoop()
}

func (p *CloudflarePool) Stop() {
	p.mu.Lock()
	if !p.running {
		p.mu.Unlock()
		return
	}
	p.running = false
	close(p.stopChan)
	p.mu.Unlock()
}

func (p *CloudflarePool) UpdateIPs(ips []string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	newMap := make(map[string]*IPStats)
	for _, ip := range ips {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			continue
		}

		if existing, ok := p.allIPs[ip]; ok {
			newMap[ip] = existing
		} else {
			newMap[ip] = &IPStats{IP: ip}
		}
	}
	p.allIPs = newMap

	// Re-filter activeIPs to remove deleted ones
	p.activeIPs = make([]*IPStats, 0)
	for _, stats := range p.allIPs {
		if stats.latencyVal > 0 && stats.Failures < 3 {
			p.activeIPs = append(p.activeIPs, stats)
		}
	}
	sort.Slice(p.activeIPs, func(i, j int) bool {
		return p.activeIPs[i].latencyVal < p.activeIPs[j].latencyVal
	})
	
	// Trigger check if we have new IPs and running? 
    // For simplicity, let the loop handle it, or we could signal.
}

// GetTopIPs returns up to n best IPs.
func (p *CloudflarePool) GetTopIPs(n int) []string {
	p.mu.RLock()
	defer p.mu.RUnlock()

	count := len(p.activeIPs)
	// Fallback to all IPs if no active ones
	if count == 0 {
		res := make([]string, 0, n)
		i := 0
		for ip := range p.allIPs {
			res = append(res, ip)
			i++
			if i >= n {
				break
			}
		}
		return res
	}

	if n > count {
		n = count
	}

	res := make([]string, n)
	for i := 0; i < n; i++ {
		res[i] = p.activeIPs[i].IP
	}
	return res
}

func (p *CloudflarePool) GetAllIPsWithStats() []*IPStats {
	p.mu.RLock()
	defer p.mu.RUnlock()

	stats := make([]*IPStats, 0, len(p.allIPs))
	for _, s := range p.allIPs {
		stats = append(stats, s)
	}

	sort.Slice(stats, func(i, j int) bool {
		// Put 0 latency (unchecked/failed) at end
		if stats[i].latencyVal == 0 {
			return false
		}
		if stats[j].latencyVal == 0 {
			return true
		}
		return stats[i].latencyVal < stats[j].latencyVal
	})

	return stats
}

func (p *CloudflarePool) healthCheckLoop() {
	// Initial check
	// p.checkAllIPs() // Move initial check to be triggered manually or by start? 
    // Usually start calls it.
    go p.checkAllIPs()

	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-p.stopChan:
			return
		case <-ticker.C:
			p.checkAllIPs()
		}
	}
}

func (p *CloudflarePool) TriggerHealthCheck() {
    go p.checkAllIPs()
}

func (p *CloudflarePool) RemoveInvalidIPs() int {
    p.mu.Lock()
    count := 0
    for ip, stats := range p.allIPs {
        if stats.Failures >= 3 {
             delete(p.allIPs, ip)
             count++
        }
    }
    p.mu.Unlock()
    
    if count > 0 {
        p.rebuildActiveIPs()
    }
    return count
}

func (p *CloudflarePool) ReportFailure(ip string) {
	p.mu.Lock()
	if stats, ok := p.allIPs[ip]; ok {
		stats.Failures++
		stats.latencyVal += 1000 * time.Millisecond // Penalize latency
		stats.Latency = stats.latencyVal.String()
	}
	p.mu.Unlock()
	p.rebuildActiveIPs()
}

func (p *CloudflarePool) ReportSuccess(ip string) {
	p.mu.Lock()
	if stats, ok := p.allIPs[ip]; ok {
		if stats.Failures > 0 {
			stats.Failures--
		}
	}
	p.mu.Unlock()
}

func (p *CloudflarePool) checkAllIPs() {
	p.mu.RLock()
	ipsToCheck := make([]string, 0, len(p.allIPs))
	for ip := range p.allIPs {
		ipsToCheck = append(ipsToCheck, ip)
	}
	p.mu.RUnlock()

	if len(ipsToCheck) == 0 {
		return
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, 10) // Concurrency limit

	for _, ip := range ipsToCheck {
		wg.Add(1)
		sem <- struct{}{}
		go func(targetIP string) {
			defer wg.Done()
			defer func() { <-sem }()

			latency, err := p.testIP(targetIP)

			p.mu.Lock()
			stats, ok := p.allIPs[targetIP]
			if ok {
				now := time.Now()
				stats.LastCheck = now.Format(time.RFC3339)
				if err != nil {
					stats.Failures++
					stats.latencyVal = 0 // Invalid
					stats.Latency = ""
				} else {
					stats.Failures = 0
					stats.latencyVal = latency
					stats.Latency = latency.String()
				}
			}
			p.mu.Unlock()
		}(ip)
	}
	wg.Wait()

	p.rebuildActiveIPs()
}

func (p *CloudflarePool) rebuildActiveIPs() {
	p.mu.Lock()
	defer p.mu.Unlock()

	newActive := make([]*IPStats, 0)
	for _, stats := range p.allIPs {
		if stats.latencyVal > 0 && stats.Failures < 3 {
			newActive = append(newActive, stats)
		}
	}

	sort.Slice(newActive, func(i, j int) bool {
		return newActive[i].latencyVal < newActive[j].latencyVal
	})

	p.activeIPs = newActive
}

func (p *CloudflarePool) testIP(ip string) (time.Duration, error) {
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	start := time.Now()
	
	conn, err := dialer.Dial("tcp", net.JoinHostPort(ip, "443"))
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	return time.Since(start), nil
}

type apiIPInfo struct {
	IP string `json:"ip"`
}

type cfApiResponse struct {
	Status bool                      `json:"status"`
	Code   int                       `json:"code"`
	Msg    string                    `json:"msg"`
	Info   map[string][]apiIPInfo    `json:"info"`
}

func FetchCloudflareIPs(apiKey string) ([]string, error) {
	if apiKey == "" {
		apiKey = "o1zrmHAF" // Default key provided by user
	}
	url := fmt.Sprintf("https://www.wetest.vip/api/cf2dns/get_cloudflare_ip?key=%s&type=v4", apiKey)

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // Avoid schannel errors on some systems
		},
	}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var apiRes cfApiResponse
	if err := json.Unmarshal(body, &apiRes); err != nil {
		return nil, fmt.Errorf("failed to parse API response: %w", err)
	}

	if !apiRes.Status || apiRes.Code != 200 {
		return nil, fmt.Errorf("API error: %s (code %d)", apiRes.Msg, apiRes.Code)
	}

	var ips []string
	for _, list := range apiRes.Info {
		for _, item := range list {
			if item.IP != "" {
				ips = append(ips, item.IP)
			}
		}
	}

	return ips, nil
}
