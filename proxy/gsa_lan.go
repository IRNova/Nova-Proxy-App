package proxy

import (
	"fmt"
	"log"
	"net"
	"os"
	"strings"
)

func gsaLogLANAccess(host string, port int) {
	lanIPs := gsaGetLANIPs()
	if len(lanIPs) == 0 {
		log.Printf("[GSA-LAN] No LAN IPs detected — GSA proxy only available on %s:%d", host, port)
		return
	}
	addrs := make([]string, 0, len(lanIPs))
	for _, ip := range lanIPs {
		addrs = append(addrs, fmt.Sprintf("%s:%d", ip, port))
	}
	log.Printf("[GSA-LAN] GSA proxy available on LAN via:")
	for _, addr := range addrs {
		log.Printf("[GSA-LAN]   http://%s", addr)
	}
	if host == "127.0.0.1" || host == "localhost" {
		log.Printf("[GSA-LAN] WARNING: listen_host is %s — LAN access requires 0.0.0.0 or a specific LAN IP", host)
	}
}

func gsaGetLANIPs() []string {
	host, _ := os.Hostname()
	seen := map[string]bool{}
	var ips []string

	if host != "" {
		if addrs, err := net.LookupIP(host); err == nil {
			for _, a := range addrs {
				if a4 := a.To4(); a4 != nil {
					ipStr := a4.String()
					if !seen[ipStr] && !strings.HasPrefix(ipStr, "127.") {
						seen[ipStr] = true
						ips = append(ips, ipStr)
					}
				}
			}
		}
	}

	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			if a4 := ipnet.IP.To4(); a4 != nil {
				ipStr := a4.String()
				if !seen[ipStr] && !strings.HasPrefix(ipStr, "127.") {
					seen[ipStr] = true
					ips = append(ips, ipStr)
				}
			}
		}
	}

	return ips
}
