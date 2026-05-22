package proxy

import (
	"fmt"
	"net"
	"net/netip"
	"os"

	"novaproxy/logging"
)

var lanLog = logging.Get("GAS-LAN")

func gasLogLANAccess(host string, port int) {
	lanIPs := gasGetLANIPs()
	if len(lanIPs) == 0 {
		lanLog.Infof("No LAN IPs detected — GAS proxy only available on %s:%d", host, port)
		return
	}
	addrs := make([]string, 0, len(lanIPs))
	for _, ip := range lanIPs {
		addrs = append(addrs, fmt.Sprintf("%s:%d", ip, port))
	}
	lanLog.Infof("GAS proxy available on LAN via:")
	for _, addr := range addrs {
		lanLog.Infof("  http://%s", addr)
	}
	if host == "127.0.0.1" || host == "localhost" {
		lanLog.Warnf("listen_host is %s — LAN access requires 0.0.0.0 or a specific LAN IP", host)
	}
}

func gasGetLANIPs() []string {
	seen := map[string]bool{}
	var ips []string

	// 1) Primary IPv4 via UDP dial to a non-routable address
	if primary := gasPrimaryIPv4(); primary != "" && !seen[primary] {
		seen[primary] = true
		if isPrivateIPv4(primary) {
			ips = append(ips, primary)
		}
	}

	// 2) Hostname lookups
	host, _ := os.Hostname()
	if host != "" {
		if addrs, err := net.LookupIP(host); err == nil {
			for _, a := range addrs {
				if a4 := a.To4(); a4 != nil {
					ipStr := a4.String()
					if !seen[ipStr] && isPrivateIPv4(ipStr) {
						seen[ipStr] = true
						ips = append(ips, ipStr)
					}
				}
			}
		}
	}

	// 3) Network interface enumeration
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
				if !seen[ipStr] && isPrivateIPv4(ipStr) {
					seen[ipStr] = true
					ips = append(ips, ipStr)
				}
			}
		}
	}

	return ips
}

func gasPrimaryIPv4() string {
	conn, err := net.Dial("udp", "192.0.2.1:80")
	if err != nil {
		return ""
	}
	defer conn.Close()
	local := conn.LocalAddr().(*net.UDPAddr)
	return local.IP.String()
}

func isPrivateIPv4(ipStr string) bool {
	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		return false
	}
	if !addr.Is4() {
		return false
	}
	return addr.IsPrivate() || addr.IsLinkLocalUnicast()
}

func gasLogSOCKS5LANAccess(host string, port int) {
	lanIPs := gasGetLANIPs()
	if len(lanIPs) == 0 {
		lanLog.Infof("No LAN IPs detected — SOCKS5 proxy only available on %s:%d", host, port)
		return
	}
	addrs := make([]string, 0, len(lanIPs))
	for _, ip := range lanIPs {
		addrs = append(addrs, fmt.Sprintf("%s:%d", ip, port))
	}
	lanLog.Infof("SOCKS5 proxy available on LAN via:")
	for _, addr := range addrs {
		lanLog.Infof("  socks5://%s", addr)
	}
}
