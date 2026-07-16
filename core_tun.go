package main

import (
	"novaproxy/proxy"
)

// externalMihomoManager wraps proxy.ExternalTunManager to manage TUN mode
type externalMihomoManager struct {
	inner *proxy.ExternalTunManager
}

func newExternalMihomoManager() *externalMihomoManager {
	return &externalMihomoManager{
		inner: proxy.NewExternalTunManager(),
	}
}

func (m *externalMihomoManager) Start(cfg proxy.TUNConfig, listenPort string, logFn func(string)) error {
	return m.inner.Start(cfg, listenPort, logFn)
}

func (m *externalMihomoManager) Stop(logFn func(string)) error {
	return m.inner.Stop(logFn)
}

func (m *externalMihomoManager) RestartIfRunning(cfg proxy.TUNConfig, listenPort string, logFn func(string)) error {
	return m.inner.RestartIfRunning(cfg, listenPort, logFn)
}

func (m *externalMihomoManager) Status(cfg proxy.TUNConfig) proxy.TUNStatus {
	return m.inner.Status(cfg)
}
