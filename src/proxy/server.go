package proxy

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/TheCanniball/CipherGate/src/core"
	"github.com/TheCanniball/CipherGate/src/relay"
)

type Server struct {
	cfg    *core.ProxyConfig
	relay  *relay.Engine
	ln     net.Listener
	mitm   *MITM
	wg     sync.WaitGroup
	stopCh chan struct{}
}

func NewServer(cfg *core.ProxyConfig, re *relay.Engine) *Server {
	var m *MITM
	if cfg.MITM != nil && cfg.MITM.Enabled {
		m = NewMITM(cfg.MITM)
	}
	return &Server{
		cfg:    cfg,
		relay:  re,
		mitm:   m,
		stopCh: make(chan struct{}),
	}
}

func (s *Server) Start() error {
	addr := fmt.Sprintf("%s:%d", s.cfg.Host, s.cfg.Port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("proxy listen: %w", err)
	}
	s.ln = ln
	s.wg.Add(1)
	go s.acceptLoop()
	if s.cfg.SOCKS5 != nil && s.cfg.SOCKS5.Enabled {
		go s.startSOCKS5()
	}
	return nil
}

func (s *Server) Stop() {
	close(s.stopCh)
	if s.ln != nil {
		s.ln.Close()
	}
	s.wg.Wait()
}

func (s *Server) acceptLoop() {
	defer s.wg.Done()
	var delay time.Duration
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			if strings.Contains(err.Error(), "use of closed network connection") {
				return
			}
			delay += 100 * time.Millisecond
			if delay > 5*time.Second {
				delay = 5 * time.Second
			}
			time.Sleep(delay)
			continue
		}
		delay = 0
		s.wg.Add(1)
		go s.handleConn(conn)
	}
}

func (s *Server) handleConn(conn net.Conn) {
	defer s.wg.Done()
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}

	switch req.Method {
	case "CONNECT":
		s.handleTunnel(conn, req)
	default:
		s.handleProxy(conn, req)
	}
}

func (s *Server) handleTunnel(conn net.Conn, req *http.Request) {
	hijackedConn, ok := conn.(*net.TCPConn)
	if !ok {
		httpError(conn, 500, "hijack failed")
		return
	}

	target := req.Host
	if !strings.Contains(target, ":") {
		target += ":443"
	}

	if s.mitm != nil && s.shouldMITM(target) {
		s.mitm.HandleTunnel(hijackedConn, target)
		return
	}

	conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	remote, err := net.DialTimeout("tcp", target, 15*time.Second)
	if err != nil {
		httpError(conn, 502, err.Error())
		return
	}
	defer remote.Close()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { io.Copy(remote, hijackedConn); wg.Done() }()
	go func() { io.Copy(hijackedConn, remote); wg.Done() }()
	wg.Wait()
}

func (s *Server) handleProxy(conn net.Conn, req *http.Request) {
	if req.URL == nil {
		httpError(conn, 400, "bad request")
		return
	}

	targetURL := req.URL.String()
	headers := make(map[string]string)
	for k, v := range req.Header {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}

	body, _ := io.ReadAll(req.Body)
	req.Body.Close()

	resp := s.relay.Relay(req.Method, targetURL, headers, body)
	if len(resp) > 0 {
		conn.Write(resp)
	}
}

func (s *Server) shouldMITM(target string) bool {
	if strings.Contains(target, "google.com") ||
		strings.Contains(target, "gstatic.com") ||
		strings.Contains(target, "youtube.com") {
		return false
	}
	return true
}

func (s *Server) startSOCKS5() {
	cfg := s.cfg.SOCKS5
	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return
	}
	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go s.handleSOCKS5(conn)
	}
}

func (s *Server) handleSOCKS5(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n < 2 {
		return
	}
	conn.Write([]byte{0x05, 0x00})

	n, err = conn.Read(buf)
	if err != nil || n < 7 {
		return
	}
	if buf[1] != 0x01 {
		return
	}
	hostLen := int(buf[4])
	host := string(buf[5 : 5+hostLen])
	port := int(buf[5+hostLen])<<8 | int(buf[5+hostLen+1])
	target := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	remote, err := net.DialTimeout("tcp", target, 15*time.Second)
	if err != nil {
		conn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return
	}
	defer remote.Close()
	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { io.Copy(remote, conn); wg.Done() }()
	go func() { io.Copy(conn, remote); wg.Done() }()
	wg.Wait()
}

func httpError(conn net.Conn, status int, msg string) {
	resp := fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Length: %d\r\n\r\n%s", status, http.StatusText(status), len(msg), msg)
	conn.Write([]byte(resp))
}
