package core

import (
	"crypto/tls"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"
)

type IPResult struct {
	IP      string `json:"ip"`
	Latency int64  `json:"latency_ms"`
	Domain  string `json:"domain"`
	Error   string `json:"error,omitempty"`
}

func ScanGoogleIPs(frontDomain string) []IPResult {
	if frontDomain == "" {
		frontDomain = "www.google.com"
	}
	fmt.Printf("\nScanning %d IPs (SNI: %s)...\n\n", len(CandidateIPs), frontDomain)

	var mu sync.Mutex
	results := make([]IPResult, 0)
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)

	for _, ip := range CandidateIPs {
		sem <- struct{}{}
		wg.Add(1)
		go func(ip string) {
			defer func() { <-sem; wg.Done() }()
			start := time.Now()
			conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, "443"), 4*time.Second)
			if err != nil {
				mu.Lock()
				results = append(results, IPResult{IP: ip, Error: err.Error()})
				mu.Unlock()
				return
			}
			tlsCfg := &tls.Config{ServerName: frontDomain, InsecureSkipVerify: true}
			tlsConn := tls.Client(conn, tlsCfg)
			_ = tlsConn.SetDeadline(time.Now().Add(4 * time.Second))
			if err := tlsConn.Handshake(); err != nil {
				conn.Close()
				mu.Lock()
				results = append(results, IPResult{IP: ip, Error: err.Error()})
				mu.Unlock()
				return
			}
			req := fmt.Sprintf("HEAD / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", frontDomain)
			tlsConn.Write([]byte(req))
			resp := make([]byte, 128)
			tlsConn.Read(resp)
			tlsConn.Close()
			latency := time.Since(start).Milliseconds()
			mu.Lock()
			results = append(results, IPResult{IP: ip, Latency: latency})
			mu.Unlock()
		}(ip)
	}
	wg.Wait()

	sort.Slice(results, func(i, j int) bool {
		if results[i].Error != "" && results[j].Error == "" {
			return false
		}
		if results[i].Error == "" && results[j].Error != "" {
			return true
		}
		return results[i].Latency < results[j].Latency
	})
	return results
}

func PrintScanResults(results []IPResult) {
	fmt.Printf("%-20s %-12s %s\n", "IP", "LATENCY", "STATUS")
	fmt.Printf("%-20s %-12s %s\n", "---", "---", "---")
	ok := 0
	for _, r := range results {
		if r.Error == "" {
			fmt.Printf("%-20s %8dms   OK\n", r.IP, r.Latency)
			ok++
		} else {
			fmt.Printf("%-20s %-12s %s\n", r.IP, "---", r.Error)
		}
	}
	fmt.Printf("\nResult: %d / %d reachable\n", ok, len(results))
	if ok > 0 {
		fmt.Println("\nTop 3 fastest:")
		count := 0
		for _, r := range results {
			if r.Error == "" {
				count++
				fmt.Printf("  %d. %s (%dms)\n", count, r.IP, r.Latency)
				if count >= 3 {
					break
				}
			}
		}
	}
}
