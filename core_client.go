package main

import (
	"errors"
	"fmt"
	"net"
	"net/rpc"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"novaproxy/proxy"
)

type coreClient struct{}

func newCoreClient() *coreClient {
	return &coreClient{}
}

func (c *coreClient) dial() (*rpc.Client, error) {
	conn, err := net.DialTimeout("tcp", coreRPCAddr, 400*time.Millisecond)
	if err != nil {
		return nil, err
	}
	return rpc.NewClient(conn), nil
}

func (c *coreClient) call(method string, args any, reply any) error {
	client, err := c.dial()
	if err != nil {
		return err
	}
	defer client.Close()
	return client.Call(method, args, reply)
}

func (c *coreClient) ensureRunning() error {
	return c.ensureRunningWithElevation(false)
}

func (c *coreClient) ensureRunningWithElevation(requireElevated bool) error {
	wasLogCaptureEnabled := false
	wasProxyRunning := false
	var pong BoolReply
	if err := c.call("Core.Ping", EmptyArgs{}, &pong); err == nil && pong.Value {
		wasLogCaptureEnabled = c.IsLogCaptureEnabled()
		wasProxyRunning = c.IsProxyRunning()
		execPath, pathErr := os.Executable()
		if pathErr != nil {
			return pathErr
		}
		info, infoErr := c.getInfo()
		if infoErr == nil && sameExecutable(info.Executable, execPath) && (!requireElevated || info.Elevated) {
			return nil
		}
		var empty EmptyArgs
		_ = c.call("Core.Shutdown", EmptyArgs{}, &empty)
		for i := 0; i < 10; i++ {
			time.Sleep(100 * time.Millisecond)
			if err := c.call("Core.Ping", EmptyArgs{}, &pong); err != nil || !pong.Value {
				break
			}
		}
	}
	execPath, err := os.Executable()
	if err != nil {
		return err
	}
	if err := startCoreProcess(execPath, requireElevated); err != nil {
		return err
	}
	for i := 0; i < 30; i++ {
		time.Sleep(200 * time.Millisecond)
		if err := c.call("Core.Ping", EmptyArgs{}, &pong); err == nil && pong.Value {
			if wasLogCaptureEnabled {
				var empty EmptyArgs
				_ = c.call("Core.StartLogCapture", EmptyArgs{}, &empty)
			}
			if wasProxyRunning {
				var empty EmptyArgs
				if err := c.call("Core.StartProxy", EmptyArgs{}, &empty); err != nil {
					return fmt.Errorf("restore proxy after core restart: %w", err)
				}
			}
			if requireElevated {
				info, infoErr := c.getInfo()
				if infoErr != nil {
					return infoErr
				}
				if !info.Elevated {
					return fmt.Errorf("core restarted but is still not elevated")
				}
			}
			return nil
		}
	}
	return fmt.Errorf("core did not become ready")
}

func (c *coreClient) getInfo() (CoreInfoReply, error) {
	var reply CoreInfoReply
	err := c.call("Core.GetInfo", EmptyArgs{}, &reply)
	return reply, err
}

func (c *coreClient) reloadIfRunning() {
	var pong BoolReply
	if err := c.call("Core.Ping", EmptyArgs{}, &pong); err != nil || !pong.Value {
		return
	}
	var empty EmptyArgs
	_ = c.call("Core.ReloadConfig", EmptyArgs{}, &empty)
}

func (c *coreClient) reloadCertificateIfRunning() {
	var pong BoolReply
	if err := c.call("Core.Ping", EmptyArgs{}, &pong); err != nil || !pong.Value {
		return
	}
	var empty EmptyArgs
	_ = c.call("Core.ReloadCertificate", EmptyArgs{}, &empty)
}

func (c *coreClient) shutdownIfRunning() {
	var pong BoolReply
	if err := c.call("Core.Ping", EmptyArgs{}, &pong); err != nil || !pong.Value {
		return
	}
	var empty EmptyArgs
	_ = c.call("Core.Shutdown", EmptyArgs{}, &empty)
}

func (c *coreClient) StartProxy() error {
	if err := c.ensureRunning(); err != nil {
		return err
	}
	var empty EmptyArgs
	return c.call("Core.StartProxy", EmptyArgs{}, &empty)
}

func (c *coreClient) StopProxy() error {
	var empty EmptyArgs
	return c.call("Core.StopProxy", EmptyArgs{}, &empty)
}

func (c *coreClient) IsProxyRunning() bool {
	var reply BoolReply
	return c.call("Core.IsProxyRunning", EmptyArgs{}, &reply) == nil && reply.Value
}

func (c *coreClient) GetStats() (int64, int64, int64) {
	var reply StatsReply
	if err := c.call("Core.GetStats", EmptyArgs{}, &reply); err != nil {
		return 0, 0, 0
	}
	return reply.Down, reply.Up, reply.Etc
}

func (c *coreClient) StartTUN() error {
	if err := c.ensureRunningWithElevation(true); err != nil {
		return fmt.Errorf("ensure elevated core failed: %w", err)
	}
	var empty EmptyArgs
	if err := c.call("Core.StartTUN", EmptyArgs{}, &empty); err != nil {
		return fmt.Errorf("Core.StartTUN RPC failed: %w", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	var lastStatus proxy.TUNStatus
	for time.Now().Before(deadline) {
		time.Sleep(200 * time.Millisecond)
		status, err := c.getTUNStatusWithError()
		if err != nil {
			return fmt.Errorf("Core.GetTUNStatus RPC failed: %w", err)
		}
		lastStatus = status
		if status.Running {
			return nil
		}
		if strings.TrimSpace(status.Message) != "" &&
			!strings.EqualFold(strings.TrimSpace(status.Message), "Windows real TUN dataplane is ready") &&
			!strings.Contains(strings.ToLower(status.Message), "startup in progress") &&
			!strings.Contains(strings.ToLower(status.Message), "starting") &&
			!strings.Contains(strings.ToLower(status.Message), "creating") &&
			!strings.Contains(strings.ToLower(status.Message), "selected") &&
			!strings.Contains(strings.ToLower(status.Message), "not running") {
			return errors.New(status.Message)
		}
	}
	if strings.TrimSpace(lastStatus.Message) != "" {
		return fmt.Errorf("TUN startup failed: %s", strings.TrimSpace(lastStatus.Message))
	}
	return fmt.Errorf("TUN did not enter running state")
}

func (c *coreClient) StopTUN() error {
	var empty EmptyArgs
	return c.call("Core.StopTUN", EmptyArgs{}, &empty)
}

func (c *coreClient) GetTUNStatus() proxy.TUNStatus {
	status, err := c.getTUNStatusWithError()
	if err != nil {
		status.Supported = runtime.GOOS == "windows"
		status.Message = "Core not running"
	}
	return status
}

func (c *coreClient) getTUNStatusWithError() (proxy.TUNStatus, error) {
	var reply TUNStatusReply
	err := c.call("Core.GetTUNStatus", EmptyArgs{}, &reply)
	return reply.Status, err
}

func (c *coreClient) StartLogCapture() error {
	if err := c.ensureRunning(); err != nil {
		return err
	}
	var empty EmptyArgs
	return c.call("Core.StartLogCapture", EmptyArgs{}, &empty)
}

func (c *coreClient) StopLogCapture() error {
	var empty EmptyArgs
	return c.call("Core.StopLogCapture", EmptyArgs{}, &empty)
}

func (c *coreClient) IsLogCaptureEnabled() bool {
	var reply BoolReply
	return c.call("Core.IsLogCaptureEnabled", EmptyArgs{}, &reply) == nil && reply.Value
}

func (c *coreClient) GetRecentLogs(limit int) string {
	var reply StringReply
	_ = c.call("Core.GetRecentLogs", LogsArgs{Limit: limit}, &reply)
	return reply.Value
}

func (c *coreClient) ClearLogs() error {
	var empty EmptyArgs
	return c.call("Core.ClearLogs", EmptyArgs{}, &empty)
}

type RouteEvent struct {
	Domain string
	Mode   string
}

type RouteEventsReply struct {
	Events []RouteEvent
}

func (c *coreClient) GetRouteEvents() []RouteEvent {
	var reply RouteEventsReply
	if err := c.call("Core.GetRouteEvents", EmptyArgs{}, &reply); err != nil {
		return nil
	}
	return reply.Events
}

func (c *coreClient) SetProxyMode(mode string) error {
	if err := c.ensureRunning(); err != nil {
		return err
	}
	var empty EmptyArgs
	return c.call("Core.SetProxyMode", SetModeArgs{Mode: mode}, &empty)
}

func (c *coreClient) GetProxyMode() string {
	var reply StringReply
	_ = c.call("Core.GetProxyMode", EmptyArgs{}, &reply)
	return reply.Value
}

func (c *coreClient) Ping() bool {
	var reply BoolReply
	return c.call("Core.Ping", EmptyArgs{}, &reply) == nil && reply.Value
}

func (c *coreClient) SetGSADialAddr(addr string) error {
	var empty EmptyArgs
	return c.call("Core.SetGSADialAddr", SetGSADialAddrArgs{Addr: addr}, &empty)
}

func sameExecutable(left, right string) bool {
	left = strings.TrimSpace(left)
	right = strings.TrimSpace(right)
	if left == "" || right == "" {
		return false
	}
	left = filepath.Clean(strings.ToLower(left))
	right = filepath.Clean(strings.ToLower(right))
	return left == right
}
