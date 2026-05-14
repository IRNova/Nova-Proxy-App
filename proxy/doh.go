package proxy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// FailoverResolver handles DNS resolution via a list of DNS nodes.
// It iterates through configured DNSNodes in order. For high availability,
// it queries the first node natively, and if it fails, falls back to remaining nodes.
type FailoverResolver struct {
	proxy    *ProxyServer
}

func NewFailoverResolver(p *ProxyServer) *FailoverResolver {
	return &FailoverResolver{
		proxy: p,
	}
}

// getNodeClient creates a configured http.Client for the given DNSNode leveraging ProxyServer's networking.
func (r *FailoverResolver) getNodeClient(ctx context.Context, node DNSNode) (*http.Client, error) {
	parsedURL, err := url.Parse(node.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid node URL: %w", err)
	}
	host := parsedURL.Hostname()

	rule := Rule{
		SniFake:       node.SNI,
		ECHEnabled:    node.ECHEnabled,
		ECHProfileID:  node.ECHProfileID,
		CertVerify:    node.CertVerify,
		ECHAutoUpdate: node.ECHAutoUpdate,
	}
	if rule.SniFake == "" {
		rule.SniFake = host // Fallback to URL host for TLS ServerName
		rule.SniPolicy = "upstream"
	} else {
		rule.SniPolicy = "fake"
	}

	if node.QUIC {
		// Note: static IPs are not fully supported for QUIC DoH nodes yet because newQUICRoundTripper computes candidates itself.
		// A potential future enhancement is passing node.IPs into a customized QUIC roundtripper.
		tr, err := r.proxy.newQUICRoundTripper(host, rule)
		if err != nil {
			return nil, err
		}
		return &http.Client{Transport: tr, Timeout: 10 * time.Second}, nil
	}

	tr := &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			var dialCandidates []string
			if len(node.IPs) > 0 {
				port := parsedURL.Port()
				if port == "" {
					port = "443"
				}
				for _, ip := range node.IPs {
					dialCandidates = append(dialCandidates, net.JoinHostPort(ip, port))
				}
			} else {
				dialCandidates = []string{addr}
			}

			var dialConn net.Conn
			var dialErr error
			for _, cand := range dialCandidates {
				dialConn, dialErr = r.proxy.dialWithRule(ctx, network, cand, rule)
				if dialErr == nil && dialConn != nil {
					break
				}
			}
			if dialErr != nil || dialConn == nil {
				return nil, fmt.Errorf("all dial candidates failed: %v", dialErr)
			}

			echBytes := r.proxy.resolveRuleECHConfig(host, rule)
			verifyName := host
			if rule.SniFake != "" {
				verifyName = rule.SniFake
			}
			// Use http/1.1 specifically to avoid h2 parsing issues when using custom DialTLSContext with uTLS,
			// matching the logic used in the successful Python test script.
			uconn := r.proxy.GetUConn(dialConn, rule.SniFake, verifyName, rule, node.CertVerify.AllowUnknownAuthority, "http/1.1", echBytes)
			if err := uconn.HandshakeContext(ctx); err != nil {
				dialConn.Close()
				return nil, err
			}
			return uconn, nil
		},
		ResponseHeaderTimeout: 5 * time.Second,
	}

	// Do not use http2.ConfigureTransport as we are strictly using HTTP/1.1 for robustness.
	return &http.Client{Transport: tr, Timeout: 10 * time.Second}, nil
}

// exchangeNode sends a single DNS query to a specific node.
func (r *FailoverResolver) exchangeNode(ctx context.Context, node *DNSNode, msg *dns.Msg) (*dns.Msg, error) {
	return r.exchangeNodeWithRetry(ctx, node, msg, true)
}

func (r *FailoverResolver) exchangeNodeWithRetry(ctx context.Context, node *DNSNode, msg *dns.Msg, allowRetry bool) (*dns.Msg, error) {
	client, err := r.getNodeClient(ctx, *node)
	if err != nil {
		return nil, err
	}

	// RFC 8484 Section 4.1: DNS ID SHOULD be set to 0 for DoH requests.
	msg = msg.Copy()
	msg.Id = 0

	buf, err := msg.Pack()
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", node.URL, bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}

	// For IP-based URLs with SNI spoofing, we must ensure the Host header matches the certificate.
	if node.SNI != "" {
		u, _ := url.Parse(node.URL)
		if u != nil && isLiteralIP(u.Hostname()) {
			req.Host = node.SNI
		}
	}

	req.ContentLength = int64(len(buf))
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 NovaProxy/1.0")

	resp, err := client.Do(req)
	if err != nil {
		// Detect ECH / TLS failures
		if allowRetry && node.ECHEnabled && node.ECHAutoUpdate {
			parsedURL, _ := url.Parse(node.URL)
			if parsedURL != nil {
				host := parsedURL.Hostname()
				log.Printf("[DOH] Handshake failed for %s, attempting ECH refresh from safe source...", host)
				
				// Try fetching fresh ECH for the DoH node itself using safe resolvers
				newECH, refreshErr := r.ResolveECHSafe(ctx, host)
				if refreshErr == nil && len(newECH) > 0 {
					log.Printf("[DOH] Successfully refreshed ECH for %s (%d bytes). Syncing to profile and retrying...", host, len(newECH))
					if node.ECHProfileID != "" {
						r.proxy.UpdateECHProfileConfig(node.ECHProfileID, newECH)
					}
					return r.exchangeNodeWithRetry(ctx, node, msg, false)
				} else if refreshErr != nil {
					log.Printf("[DOH] ECH refresh failed for %s: %v", host, refreshErr)
				}
			}
		}
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

// exchange issues the DNS query with failover logic.
func (r *FailoverResolver) exchange(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	var nodes []DNSNode
	if r.proxy != nil && r.proxy.rules != nil {
		nodes = r.proxy.rules.GetDNSNodes()
	}

	var activeNodes []DNSNode
	for _, n := range nodes {
		if !n.Enabled {
			continue
		}
		activeNodes = append(activeNodes, n)
	}

	// Use normal active nodes first
	if len(activeNodes) > 0 {
		// Step 1: Query the highest priority node
		primary := &activeNodes[0]
		resp, primaryErr := r.exchangeNode(ctx, primary, msg)
		if primaryErr == nil && resp != nil {
			return resp, nil
		}

		// Step 2: Parallel race between remaining active nodes
		if len(activeNodes) > 1 {
			type result struct {
				msg *dns.Msg
				err error
			}
			resChan := make(chan result, len(activeNodes)-1)
			ctxCancel, cancel := context.WithCancel(ctx)
			defer cancel()

			for i, node := range activeNodes[1:] {
				go func(idx int, n DNSNode) {
					m, e := r.exchangeNode(ctxCancel, &activeNodes[idx+1], msg)
					if e == nil && m != nil {
						resChan <- result{m, nil}
						cancel()
					} else {
						resChan <- result{nil, e}
					}
				}(i, node)
			}

			for i := 0; i < len(activeNodes)-1; i++ {
				select {
				case res := <-resChan:
					if res.err == nil {
						return res.msg, nil
					}
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
		}
	}

	// Step 4: Final fallback to System DNS
	// Note: Standard library doesn't expose a clean DoH-like exchange for raw dns.Msg.
	// We'll perform a standard lookup based on the first question.
	if len(msg.Question) > 0 {
		target := msg.Question[0].Name
		switch msg.Question[0].Qtype {
		case dns.TypeA, dns.TypeAAAA:
			ips, err := net.LookupIP(strings.TrimSuffix(target, "."))
			if err == nil && len(ips) > 0 {
				reply := new(dns.Msg)
				reply.SetReply(msg)
				for _, ip := range ips {
					if ip4 := ip.To4(); ip4 != nil && msg.Question[0].Qtype == dns.TypeA {
						reply.Answer = append(reply.Answer, &dns.A{
							Hdr: dns.RR_Header{Name: target, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
							A:   ip4,
						})
					} else if ip6 := ip.To16(); ip6 != nil && msg.Question[0].Qtype == dns.TypeAAAA {
						reply.Answer = append(reply.Answer, &dns.AAAA{
							Hdr:  dns.RR_Header{Name: target, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
							AAAA: ip6,
						})
					}
				}
				return reply, nil
			}
		}
	}

	return nil, fmt.Errorf("all DNS resolution attempts failed (tried %d active nodes and system DNS)", len(activeNodes))
}

// ResolveECH fetches the ECH config for a domain via TypeHTTPS (65)
func (r *FailoverResolver) ResolveECH(ctx context.Context, domain string) ([]byte, error) {
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
					return ech.ECH, nil
				}
			}
		}
	}
	return nil, fmt.Errorf("no ECH config found for %s", domain)
}

// exchangeSafe issues the DNS query ONLY using nodes that don't have ECH enabled.
// This is used to break the chicken-and-egg problem when ECH configs expire.
func (r *FailoverResolver) exchangeSafe(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	var nodes []DNSNode
	if r.proxy != nil && r.proxy.rules != nil {
		nodes = r.proxy.rules.GetDNSNodes()
	}

	var safeNodes []*DNSNode
	for i := range nodes {
		if nodes[i].Enabled && !nodes[i].ECHEnabled {
			safeNodes = append(safeNodes, &nodes[i])
		}
	}

	if len(safeNodes) == 0 {
		return nil, fmt.Errorf("no safe (non-ECH) DNS nodes available for fallback")
	}

	// Try in order
	for _, node := range safeNodes {
		resp, err := r.exchangeNodeWithRetry(ctx, node, msg, false)
		if err == nil {
			return resp, nil
		}
	}

	return nil, fmt.Errorf("all safe DNS resolution attempts failed")
}


// ResolveECHSafe fetches the ECH config for a domain via standard nodes (no ECH).
func (r *FailoverResolver) ResolveECHSafe(ctx context.Context, domain string) ([]byte, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeHTTPS)

	resp, err := r.exchangeSafe(ctx, msg)
	if err != nil {
		return nil, err
	}

	for _, ans := range resp.Answer {
		if https, ok := ans.(*dns.HTTPS); ok {
			for _, opt := range https.Value {
				if ech, ok := opt.(*dns.SVCBECHConfig); ok {
					return ech.ECH, nil
				}
			}
		}
	}
	return nil, fmt.Errorf("no ECH config found via safe source for %s", domain)
}

// TestNode performs a query strictly against a single node, bypassing failover logic.
// Useful for the frontend Connectivity Test feature.
func (r *FailoverResolver) TestNode(ctx context.Context, node DNSNode) ([]string, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn("cloudflare.com"), dns.TypeA)

	resp, err := r.exchangeNode(ctx, &node, msg)
	if err != nil {
		return nil, err
	}

	var ips []string
	for _, ans := range resp.Answer {
		if a, ok := ans.(*dns.A); ok {
			ips = append(ips, a.A.String())
		}
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no A records returned")
	}
	return ips, nil
}

// ResolveIPs fetches IP records via DoH.
func (r *FailoverResolver) ResolveIPs(ctx context.Context, domain string) ([]string, error) {
	// Simple caching could be added here, but OS/Browser generally do it anyway.
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
func (r *FailoverResolver) ResolveIPAddrs(ctx context.Context, domain string) ([]net.IP, error) {
	// Prevent circular loops: if the targeted domain is our DoH endpoint itself,
	// do not resolve. But FailoverResolver uses node.IPs over dialCandidates natively! 
	// The only circular loop is if node.IPs is empty and SNI needs to be resolved by system DNS.
	
	// Filter out loops (fast check)
	isDoHNode := false
	if r.proxy != nil && r.proxy.rules != nil {
		for _, n := range r.proxy.rules.GetDNSNodes() {
			u, err := url.Parse(n.URL)
			if err == nil {
				h := u.Hostname()
				if strings.EqualFold(h, domain) || strings.EqualFold(h, strings.TrimSuffix(domain, ".")) {
					isDoHNode = true
					break
				}
			}
		}
	}
	if isDoHNode {
		// A fallback to system lookup to break the loop, but usually Node IPs are strictly enforced
		sysIPs, err := net.LookupIP(domain)
		if err == nil && len(sysIPs) > 0 {
			return sysIPs, nil
		}
	}

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
	var wg sync.WaitGroup
	var mapMs sync.Mutex

	// Wait, making Parallel queries for A/AAAA speeds things up
	wg.Add(2)
	go func() {
		defer wg.Done()
		if err := lookup(dns.TypeA); err != nil {
			mapMs.Lock()
			errs = append(errs, err)
			mapMs.Unlock()
		}
	}()
	go func() {
		defer wg.Done()
		if err := lookup(dns.TypeAAAA); err != nil {
			mapMs.Lock()
			errs = append(errs, err)
			mapMs.Unlock()
		}
	}()
	wg.Wait()

	if len(ips) > 0 {
		return ips, nil
	}
	if len(errs) > 0 {
		return nil, errs[0]
	}
	return nil, fmt.Errorf("no IP records found for %s", domain)
}
