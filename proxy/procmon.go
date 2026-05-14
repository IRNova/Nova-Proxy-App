package proxy

import (
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type ProcessInfo struct {
	PID       int32  `json:"pid"`
	Name      string `json:"name"`
	DownBytes int64  `json:"down_bytes"`
	UpBytes   int64  `json:"up_bytes"`
	IsActive  bool   `json:"is_active"`
}

type procConnTrack struct {
	pid       int32
	downBytes int64
	upBytes   int64
	lastSeen  time.Time
}

type ProcessMonitor struct {
	mu         sync.RWMutex
	conns      map[string]*procConnTrack
	processes  map[int32]*ProcessInfo
	proxyPort  int
	stopCh     chan struct{}
	tcpFetcher func() (map[string]int32, error)
	pidLister  func() []int32
}

func NewProcessMonitor(proxyPort int) *ProcessMonitor {
	return &ProcessMonitor{
		conns:    make(map[string]*procConnTrack),
		processes: make(map[int32]*ProcessInfo),
		proxyPort: proxyPort,
		stopCh:   make(chan struct{}),
	}
}

func (pm *ProcessMonitor) SetTCPFetcher(fn func() (map[string]int32, error)) {
	pm.tcpFetcher = fn
}

func (pm *ProcessMonitor) SetPIDLister(fn func() []int32) {
	pm.pidLister = fn
}

func (pm *ProcessMonitor) Start() {
	if pm.tcpFetcher == nil {
		return
	}
	ticker := time.NewTicker(3 * time.Second)
	for {
		select {
		case <-ticker.C:
			pm.refresh()
		case <-pm.stopCh:
			ticker.Stop()
			return
		}
	}
}

func (pm *ProcessMonitor) Stop() {
	close(pm.stopCh)
}

func (pm *ProcessMonitor) TrackConnection(clientAddr string) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	if _, exists := pm.conns[clientAddr]; !exists {
		pm.conns[clientAddr] = &procConnTrack{pid: -1, lastSeen: time.Now()}
	}
}

func (pm *ProcessMonitor) RecordBytes(clientAddr string, down, up int64) {
	pm.mu.RLock()
	ct, ok := pm.conns[clientAddr]
	pm.mu.RUnlock()
	if ok && ct.pid > 0 {
		atomic.AddInt64(&ct.downBytes, down)
		atomic.AddInt64(&ct.upBytes, up)
		ct.lastSeen = time.Now()
	}
}

func (pm *ProcessMonitor) refresh() {
	portMap, err := pm.tcpFetcher()
	if err != nil {
		return
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()

	now := time.Now()

	for addr, ct := range pm.conns {
		_, portStr, err := net.SplitHostPort(addr)
		if err != nil {
			continue
		}
		if pid, ok := portMap[portStr]; ok {
			ct.pid = pid
			ct.lastSeen = now
		}
	}

	pidBytes := make(map[int32]*ProcessInfo)

	// 1. Build from active proxy connections
	for _, ct := range pm.conns {
		if ct.pid <= 0 {
			continue
		}
		pi, ok := pidBytes[ct.pid]
		if !ok {
			pi = &ProcessInfo{PID: ct.pid, IsActive: true}
			if existing, found := pm.processes[ct.pid]; found {
				pi.Name = existing.Name
			}
			pidBytes[ct.pid] = pi
		}
		pi.DownBytes += atomic.LoadInt64(&ct.downBytes)
		pi.UpBytes += atomic.LoadInt64(&ct.upBytes)
		if now.Sub(ct.lastSeen) > 6*time.Second {
			pi.IsActive = false
		}
	}

	// 2. Merge in all known system processes (for proxy app selection UI)
	if pm.pidLister != nil {
		knownPids := pm.pidLister()
		for _, pid := range knownPids {
			if _, exists := pidBytes[pid]; !exists {
				// Use a cached name if available, otherwise the lister will populate it
				name := ""
				if existing, found := pm.processes[pid]; found {
					name = existing.Name
				}
				pidBytes[pid] = &ProcessInfo{PID: pid, Name: name, IsActive: false}
			}
		}
	}

	// Preserve process names from previous cycles
	for pid, pi := range pidBytes {
		if pi.Name == "" {
			if existing, ok := pm.processes[pid]; ok {
				pi.Name = existing.Name
			}
		}
	}

	pm.processes = pidBytes
}

func (pm *ProcessMonitor) GetProcesses() []ProcessInfo {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	res := make([]ProcessInfo, 0, len(pm.processes))
	for _, pi := range pm.processes {
		res = append(res, *pi)
	}
	return res
}
