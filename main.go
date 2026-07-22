package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/TheCanniball/CipherGate/src/core"
	"github.com/TheCanniball/CipherGate/src/proxy"
	"github.com/TheCanniball/CipherGate/src/relay"
	"github.com/TheCanniball/CipherGate/src/admin"
)

var version = "1.0.0"

func main() {
	configPath := flag.String("c", "config/config.json", "config file path")
	showVersion := flag.Bool("v", false, "show version")
	scanIPs := flag.Bool("scan", false, "scan Google IPs")
	guiMode := flag.Bool("desktop", false, "launch desktop GUI")
	flag.Parse()

	if *showVersion {
		fmt.Printf("CipherGate v%s\n", version)
		return
	}

	cfg := core.LoadConfig(*configPath)

	if *guiMode {
		cfg.Admin.Enabled = false
		runDesktop(cfg)
		return
	}

	if *scanIPs {
		results := core.ScanGoogleIPs(cfg.FrontDomain)
		core.PrintScanResults(results)
		return
	}

	relayEngine := relay.NewEngine(cfg)
	proxyServer := proxy.NewServer(&cfg.Proxy, relayEngine)
	var adminServer *admin.Server
	if cfg.Admin.Enabled {
		adminServer = admin.NewServer(&cfg.Admin, relayEngine)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go relayEngine.Start()
	go proxyServer.Start()
	if adminServer != nil {
		go adminServer.Start()
	}

	<-sigCh
	fmt.Println("\nShutting down...")
	if adminServer != nil {
		adminServer.Stop()
	}
	proxyServer.Stop()
	relayEngine.Stop()
}
