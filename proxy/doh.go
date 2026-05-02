package proxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type DoHResolver struct {
	ServerURL string
	Client    *http.Client
	echCache  sync.Map // domain -> []byte
}

func NewDoHResolver(url string) *DoHResolver {
	if url == "" {
		url = "https://223.5.5.5/dns-query" // Default Alidns
	}
	return &DoHResolver{
		ServerURL: url,
		Client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// ResolveECH fetches the ECH config for a domain via TypeHTTPS (65)
func (r *DoHResolver) ResolveECH(ctx context.Context, domain string) ([]byte, error) {
	if val, ok := r.echCache.Load(domain); ok {
		return val.([]byte), nil
	}

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeHTTPS)

	resp, err := r.exchange(ctx, msg)
	if err != nil {
		return nil, err
	}

	for _, ans := range resp.Answer {
		if https, ok := ans.(*dns.HTTPS); ok {
			for _, opt := range https.Value {
				if ech, ok := opt.(*dns.SVCBECHConfig); ok {
					r.echCache.Store(domain, ech.ECH)
					return ech.ECH, nil
				}
			}
		}
	}
	return nil, fmt.Errorf("no ECH config found for %s", domain)
}

// ResolveIPs fetches IP records via DoH.
func (r *DoHResolver) ResolveIPs(ctx context.Context, domain string) ([]string, error) {
	ipAddrs, err := r.ResolveIPAddrs(ctx, domain)
	if err != nil {
		return nil, err
	}

	ips := make([]string, 0, len(ipAddrs))
	for _, ip := range ipAddrs {
		if ip == nil {
			continue
		}
		ips = append(ips, ip.String())
	}
	return ips, nil
}

// ResolveIPAddrs fetches both A and AAAA records via DoH.
func (r *DoHResolver) ResolveIPAddrs(ctx context.Context, domain string) ([]net.IP, error) {
	var ips []net.IP

	lookup := func(qtype uint16) error {
		msg := new(dns.Msg)
		msg.SetQuestion(dns.Fqdn(domain), qtype)

		resp, err := r.exchange(ctx, msg)
		if err != nil {
			return err
		}

		for _, ans := range resp.Answer {
			switch rr := ans.(type) {
			case *dns.A:
				ips = append(ips, rr.A)
			case *dns.AAAA:
				ips = append(ips, rr.AAAA)
			}
		}
		return nil
	}

	var errs []error
	if err := lookup(dns.TypeA); err != nil {
		errs = append(errs, err)
	}
	if err := lookup(dns.TypeAAAA); err != nil {
		errs = append(errs, err)
	}

	if len(ips) > 0 {
		return ips, nil
	}
	if len(errs) > 0 {
		return nil, errs[0]
	}
	return nil, fmt.Errorf("no IP records found for %s", domain)
}

func (r *DoHResolver) exchange(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	buf, err := msg.Pack()
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", r.ServerURL, nil)
	if err != nil {
		return nil, err
	}

	// Create a pipe to stream the body
	pr, pw := io.Pipe()
	go func() {
		pw.Write(buf)
		pw.Close()
	}()
	req.Body = pr
	req.ContentLength = int64(len(buf))
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := r.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH server returned status %d", resp.StatusCode)
	}

	respBuf, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	resMsg := new(dns.Msg)
	if err := resMsg.Unpack(respBuf); err != nil {
		return nil, err
	}

	return resMsg, nil
}
