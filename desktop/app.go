//go:build windows && desktop

package desktop

import (
	"fmt"
	"log"
	"net"
	"os/exec"
	"time"

	"github.com/TheCanniball/CipherGate/novapi"
	"github.com/TheCanniball/CipherGate/src/core"
	"github.com/TheCanniball/CipherGate/src/proxy"
	"github.com/TheCanniball/CipherGate/src/relay"
	"github.com/jchv/go-webview2"
	"golang.org/x/sys/windows/registry"
)

func Run(cfg *core.Config) {
	re := relay.NewEngine(cfg)
	ps := proxy.NewServer(&cfg.Proxy, re)

	rc := novapi.NewRelayController(
		func() { go re.Start() },
		func() { re.Stop() },
		func() map[string]any { return re.Stats() },
	)

	api := novapi.NewServer(cfg, rc)
	go ps.Start()

	port := 8080
	if err := api.Start(port); err != nil {
		port = 0
		if err := api.Start(port); err != nil {
			log.Fatalf("novapi: %v", err)
		}
	}
	defer ps.Stop()

	adminURL := fmt.Sprintf("http://127.0.0.1:%d/__nova/", port)
	api.AddLog("INFO", fmt.Sprintf("NovaProxy v%s ready", cfg.Version))

	for i := 0; i < 30; i++ {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 500*time.Millisecond)
		if err == nil { c.Close(); break }
		time.Sleep(500 * time.Millisecond)
	}

	if HasWebView2() {
		wvCh := make(chan webview2.WebView, 1)
		go func() {
			defer func() { recover() }()
			w := webview2.NewWithOptions(webview2.WebViewOptions{
				Debug: false, AutoFocus: true,
				WindowOptions: webview2.WindowOptions{
					Title: "NovaProxy", Width: 1280, Height: 860, Center: true,
				},
			})
			wvCh <- w
		}()

		var wv webview2.WebView
		select {
		case wv = <-wvCh:
		case <-time.After(4 * time.Second):
		}

		if wv != nil {
			defer func() { recover(); wv.Destroy() }()
			wv.SetSize(1280, 860, webview2.HintNone)
			wv.Navigate(adminURL)
			wv.Run()
			return
		}
	}

	log.Printf("Opening browser instead...")
	exec.Command("rundll32", "url.dll,FileProtocolHandler", adminURL).Start()
	fmt.Printf("NovaProxy running at %s\n", adminURL)
	select {}
}

func HasWebView2() bool {
	_, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00FB3A3A6E2E}`,
		registry.READ)
	if err == nil {
		return true
	}
	_, err = registry.OpenKey(registry.CURRENT_USER,
		`SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00FB3A3A6E2E}`,
		registry.READ)
	return err == nil
}
