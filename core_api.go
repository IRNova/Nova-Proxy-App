package main

import (
	"errors"
	"fmt"
	"net"
	"net/rpc"
	"os"
	"runtime/debug"
	"sync"

	"novaproxy/proxy"
)

const coreRPCAddr = "127.0.0.1:18933"

type coreService struct {
	runtime *coreRuntime
	stop    func()
}

type EmptyArgs struct{}

type BoolReply struct {
	Value bool
}

type StringReply struct {
	Value string
}

type StatsReply struct {
	Down int64
	Up   int64
	Etc  int64
}

type CoreInfoReply struct {
	PID        int
	Executable string
	Elevated   bool
}

type TUNStatusReply struct {
	Status proxy.TUNStatus
}

type SetModeArgs struct {
	Mode string
}

type LogsArgs struct {
	Limit int
}

type StringArgs struct {
	Value string
}

type SetGASDialAddrArgs struct {
	Addr string
}

func (s *coreService) Ping(_ EmptyArgs, reply *BoolReply) error {
	reply.Value = true
	return nil
}

func (s *coreService) GetInfo(_ EmptyArgs, reply *CoreInfoReply) error {
	reply.PID = os.Getpid()
	reply.Executable = s.runtime.execPath
	reply.Elevated = isProcessElevated()
	return nil
}

func (s *coreService) ReloadConfig(_ EmptyArgs, _ *EmptyArgs) error {
	return s.runtime.reloadConfig()
}

func (s *coreService) ReloadCertificate(_ EmptyArgs, _ *EmptyArgs) error {
	return s.runtime.reloadCertificate()
}

func (s *coreService) Shutdown(_ EmptyArgs, _ *EmptyArgs) error {
	if s.stop != nil {
		s.stop()
	}
	return nil
}

func (s *coreService) StartProxy(_ EmptyArgs, _ *EmptyArgs) error {
	return s.runtime.startProxy()
}

func (s *coreService) StopProxy(_ EmptyArgs, _ *EmptyArgs) error {
	return s.runtime.stopProxy()
}

func (s *coreService) IsProxyRunning(_ EmptyArgs, reply *BoolReply) error {
	reply.Value = s.runtime.proxyServer.IsRunning()
	return nil
}

func (s *coreService) GetStats(_ EmptyArgs, reply *StatsReply) error {
	reply.Down, reply.Up, reply.Etc = s.runtime.proxyServer.GetStats()
	return nil
}

func (s *coreService) StartTUN(_ EmptyArgs, _ *EmptyArgs) error {
	defer func() {
		if r := recover(); r != nil {
			s.runtime.failTUNStart(fmt.Errorf("core StartTUN panic: %v", r))
		}
	}()
	if err := s.runtime.startTUN(); err != nil {
		s.runtime.appendLog("[core] StartTUN failed: " + err.Error())
		return err
	}
	return nil
}

func (s *coreService) StopTUN(_ EmptyArgs, _ *EmptyArgs) error {
	go func() {
		if err := s.runtime.stopTUN(); err != nil {
			s.runtime.appendLog("[core] StopTUN failed: " + err.Error())
		}
	}()
	return nil
}

func (s *coreService) GetTUNStatus(_ EmptyArgs, reply *TUNStatusReply) error {
	reply.Status = s.runtime.getTUNStatus()
	return nil
}

func (s *coreService) StartLogCapture(_ EmptyArgs, _ *EmptyArgs) error {
	s.runtime.startLogCapture()
	return nil
}

func (s *coreService) StopLogCapture(_ EmptyArgs, _ *EmptyArgs) error {
	s.runtime.stopLogCapture()
	return nil
}

func (s *coreService) IsLogCaptureEnabled(_ EmptyArgs, reply *BoolReply) error {
	reply.Value = s.runtime.isLogCaptureEnabled()
	return nil
}

func (s *coreService) GetRecentLogs(args LogsArgs, reply *StringReply) error {
	reply.Value = s.runtime.recentLogs(args.Limit)
	return nil
}

func (s *coreService) ClearLogs(_ EmptyArgs, _ *EmptyArgs) error {
	s.runtime.clearLogs()
	return nil
}

func (s *coreService) GetRouteEvents(_ EmptyArgs, reply *RouteEventsReply) error {
	reply.Events = s.runtime.popRouteEvents()
	return nil
}

func (s *coreService) SetProxyMode(args SetModeArgs, _ *EmptyArgs) error {
	// Handle both old-style modes and new routing modes
	switch args.Mode {
	case "rule", "gas", "v2ray":
		return s.runtime.switchMode(args.Mode)
	default:
		// Legacy mode support for backward compatibility
		return s.runtime.proxyServer.SetMode(args.Mode)
	}
}

func (s *coreService) GetProxyMode(_ EmptyArgs, reply *StringReply) error {
	reply.Value = s.runtime.getCurrentMode()
	return nil
}

type SetGASRelayArgs struct {
	Enabled     bool
	GoogleIP    string
	FrontDomain string
	ScriptID    string
	ScriptIDs   []string
	AuthKey     string
	VerifySSL   bool
}

func (s *coreService) SetGASDialAddr(args SetGASDialAddrArgs, _ *EmptyArgs) error {
	s.runtime.proxyServer.SetGASDialAddr(args.Addr)
	return nil
}

func (s *coreService) SetGASRelay(args SetGASRelayArgs, _ *EmptyArgs) error {
	if !args.Enabled {
		s.runtime.proxyServer.SetGasRelay(nil)
		return nil
	}
	cfg := proxy.GASConfig{
		GoogleIP:    args.GoogleIP,
		FrontDomain: args.FrontDomain,
		ScriptID:    args.ScriptID,
		ScriptIDs:   args.ScriptIDs,
		AuthKey:     args.AuthKey,
		VerifySSL:   args.VerifySSL,
	}
	relay := proxy.NewGASRelay(cfg)
	s.runtime.proxyServer.SetGasRelay(relay)
	return nil
}

// --- V2Ray Core RPC ---

type V2RayGetConfigsReply struct {
	Configs []proxy.V2RayConfig
}

func (s *coreService) V2RayGetConfigs(_ EmptyArgs, reply *V2RayGetConfigsReply) error {
	reply.Configs = s.runtime.v2rayManager.GetConfigs()
	return nil
}

type V2RayAddConfigReply struct {
	Config *proxy.V2RayConfig
	Error  string
}

func (s *coreService) V2RayAddConfig(args StringArgs, reply *V2RayAddConfigReply) error {
	cfg, err := s.runtime.v2rayManager.AddConfig(args.Value)
	if err != nil {
		reply.Error = err.Error()
		return nil
	}
	reply.Config = cfg
	return nil
}

type V2RayIDArgs struct {
	ID string
}

func (s *coreService) V2RayDeleteConfig(args V2RayIDArgs, _ *EmptyArgs) error {
	return s.runtime.v2rayManager.DeleteConfig(args.ID)
}

func (s *coreService) V2RaySelectConfig(args V2RayIDArgs, _ *EmptyArgs) error {
	return s.runtime.v2rayManager.SelectConfig(args.ID)
}

func (s *coreService) V2RayClearConfigs(_ EmptyArgs, _ *EmptyArgs) error {
	return s.runtime.v2rayManager.ClearConfigs()
}

func (s *coreService) V2RayGetSelectedConfig(_ EmptyArgs, reply *V2RayAddConfigReply) error {
	cfg := s.runtime.v2rayManager.GetSelectedConfig()
	if cfg == nil {
		return nil
	}
	reply.Config = cfg
	return nil
}

func (s *coreService) V2RayStartCore(_ EmptyArgs, _ *EmptyArgs) error {
	s.runtime.v2rayManager.SetCoreRunning(true)
	s.runtime.v2rayManager.SetCoreActive(true)
	return nil
}

func (s *coreService) V2RayStopCore(_ EmptyArgs, _ *EmptyArgs) error {
	s.runtime.v2rayManager.SetCoreRunning(false)
	s.runtime.v2rayManager.SetCoreActive(false)
	return nil
}

type V2RayCoreStatusReply struct {
	Running bool
	Active  bool
	Port    int
}

func (s *coreService) V2RayCoreStatus(_ EmptyArgs, reply *V2RayCoreStatusReply) error {
	reply.Running = s.runtime.v2rayManager.IsCoreRunning()
	reply.Active = s.runtime.v2rayManager.IsCoreActive()
	reply.Port = s.runtime.v2rayManager.GetCorePort()
	return nil
}

type V2RaySettingsReply struct {
	Settings proxy.V2RaySettings
}

type V2RaySettingsArgs struct {
	Settings proxy.V2RaySettings
}

func (s *coreService) V2RayGetSettings(_ EmptyArgs, reply *V2RaySettingsReply) error {
	reply.Settings = s.runtime.v2rayManager.GetSettings()
	return nil
}

func (s *coreService) V2RaySaveSettings(args V2RaySettingsArgs, _ *EmptyArgs) error {
	return s.runtime.v2rayManager.SaveSettings(args.Settings)
}

func runCoreMain() error {
	runtime, err := newCoreRuntime()
	if err != nil {
		return err
	}
	defer runtime.shutdown()
	runtime.appendLog(fmt.Sprintf("[core] starting pid=%d", os.Getpid()))

	server := rpc.NewServer()
	var (
		stopOnce sync.Once
		listener net.Listener
	)
	stopFn := func() {
		stopOnce.Do(func() {
			if listener != nil {
				_ = listener.Close()
			}
		})
	}

	if err := server.RegisterName("Core", &coreService{runtime: runtime, stop: stopFn}); err != nil {
		return err
	}

	listener, err = net.Listen("tcp", coreRPCAddr)
	if err != nil {
		runtime.appendLog(fmt.Sprintf("[core] listen failed: %v", err))
		return err
	}
	defer listener.Close()
	runtime.appendLog(fmt.Sprintf("[core] listening on %s", coreRPCAddr))

	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			if ne, ok := err.(net.Error); ok && (ne.Timeout() || ne.Temporary()) {
				runtime.appendLog(fmt.Sprintf("[core] rpc accept temporary error: %v", err))
				continue
			}
			runtime.appendLog(fmt.Sprintf("[core] rpc accept error: %v", err))
			continue
		}
		go func(conn net.Conn) {
			defer func() {
				if r := recover(); r != nil {
					runtime.appendLog(fmt.Sprintf("[core] rpc panic: %v\n%s", r, string(debug.Stack())))
				}
				_ = conn.Close()
			}()
			server.ServeConn(conn)
		}(conn)
	}
}
