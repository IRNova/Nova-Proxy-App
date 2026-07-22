package tunnel

import (
	"io"
	"net"
	"sync"
)

type Tunnel struct {
	LocalAddr  string
	RemoteAddr string
	listener   net.Listener
	wg         sync.WaitGroup
	stopCh     chan struct{}
}

func New(local, remote string) *Tunnel {
	return &Tunnel{
		LocalAddr:  local,
		RemoteAddr: remote,
		stopCh:     make(chan struct{}),
	}
}

func (t *Tunnel) Start() error {
	ln, err := net.Listen("tcp", t.LocalAddr)
	if err != nil {
		return err
	}
	t.listener = ln
	t.wg.Add(1)
	go t.acceptLoop()
	return nil
}

func (t *Tunnel) Stop() {
	close(t.stopCh)
	if t.listener != nil {
		t.listener.Close()
	}
	t.wg.Wait()
}

func (t *Tunnel) acceptLoop() {
	defer t.wg.Done()
	for {
		conn, err := t.listener.Accept()
		if err != nil {
			return
		}
		go t.handleConn(conn)
	}
}

func (t *Tunnel) handleConn(incoming net.Conn) {
	defer incoming.Close()
	outgoing, err := net.Dial("tcp", t.RemoteAddr)
	if err != nil {
		return
	}
	defer outgoing.Close()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { io.Copy(outgoing, incoming); wg.Done() }()
	go func() { io.Copy(incoming, outgoing); wg.Done() }()
	wg.Wait()
}
