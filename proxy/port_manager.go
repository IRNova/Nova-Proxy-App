package proxy

import (
	"encoding/binary"
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"
)

var (
	pmModiphlpapi         = syscall.NewLazyDLL("iphlpapi.dll")
	pmGetExtendedTcpTableProc = pmModiphlpapi.NewProc("GetExtendedTcpTable")

	pmModkernel32      = syscall.NewLazyDLL("kernel32.dll")
	pmCreateToolhelp32Snapshot = pmModkernel32.NewProc("CreateToolhelp32Snapshot")
	pmProcess32First          = pmModkernel32.NewProc("Process32FirstW")
	pmProcess32Next           = pmModkernel32.NewProc("Process32NextW")
	pmOpenProcess             = pmModkernel32.NewProc("OpenProcess")
	pmCloseHandle             = pmModkernel32.NewProc("CloseHandle")

	pmModpsapi            = syscall.NewLazyDLL("psapi.dll")
	pmGetModuleBaseName   = pmModpsapi.NewProc("GetModuleBaseNameW")
)

const (
	pmAF_INET                 = 2
	pmTCP_TABLE_OWNER_PID_ALL = 5
	pmTH32CS_SNAPPROCESS      = 0x00000002
	pmPROCESS_QUERY_LIMITED_INFORMATION = 0x1000
	pmPROCESS_VM_READ         = 0x0010
)

type pmMIB_TCPROW_OWNER_PID struct {
	DwState      uint32
	DwLocalAddr  uint32
	DwLocalPort  uint32
	DwRemoteAddr uint32
	DwRemotePort uint32
	DwOwningPid  uint32
}

type pmPROCESSENTRY32W struct {
	DwSize              uint32
	CntUsage            uint32
	Th32ProcessID       uint32
	Th32DefaultHeapID   uintptr
	Th32ModuleID        uint32
	CntThreads          uint32
	Th32ParentProcessID uint32
	PcPriClassBase      int32
	DwFlags             uint32
	SzExeFile           [260]uint16
}

var (
	pmProcNameMu   sync.Mutex
	pmProcNameCache = map[uint32]string{}
	pmLastProcEnum  = time.Now()
)

func pmGetProcessName(pid uint32) string {
	pmProcNameMu.Lock()
	defer pmProcNameMu.Unlock()

	if name, ok := pmProcNameCache[pid]; ok {
		return name
	}

	handle, _, _ := pmOpenProcess.Call(pmPROCESS_QUERY_LIMITED_INFORMATION|pmPROCESS_VM_READ, 0, uintptr(pid))
	if handle == 0 {
		return ""
	}
	defer pmCloseHandle.Call(handle)

	var buf [260]uint16
	ret, _, _ := pmGetModuleBaseName.Call(handle, 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if ret == 0 {
		return ""
	}
	length := 0
	for buf[length] != 0 {
		length++
	}
	name := strings.ToLower(string(utf16.Decode(buf[:length])))
	if name != "" {
		pmProcNameCache[pid] = name
	}
	return name
}

func pmEnumerateProcesses() {
	snapshot, _, _ := pmCreateToolhelp32Snapshot.Call(pmTH32CS_SNAPPROCESS, 0)
	if snapshot == uintptr(syscall.InvalidHandle) {
		return
	}
	defer pmCloseHandle.Call(snapshot)

	activePids := make(map[uint32]bool)
	var pe pmPROCESSENTRY32W
	pe.DwSize = uint32(unsafe.Sizeof(pe))

	ret, _, _ := pmProcess32First.Call(snapshot, uintptr(unsafe.Pointer(&pe)))
	for ret != 0 {
		pid := pe.Th32ProcessID
		name := strings.ToLower(syscall.UTF16ToString(pe.SzExeFile[:]))
		if _, exists := pmProcNameCache[pid]; !exists {
			pmProcNameCache[pid] = name
		}
		activePids[pid] = true
		ret, _, _ = pmProcess32Next.Call(snapshot, uintptr(unsafe.Pointer(&pe)))
	}

	for pid := range pmProcNameCache {
		if !activePids[pid] {
			delete(pmProcNameCache, pid)
		}
	}
}

func pmGetTcpTable() ([]pmMIB_TCPROW_OWNER_PID, error) {
	var size uint32
	pmGetExtendedTcpTableProc.Call(0, uintptr(unsafe.Pointer(&size)), 0, pmAF_INET, pmTCP_TABLE_OWNER_PID_ALL, 0)
	if size == 0 {
		return nil, fmt.Errorf("failed to get table size")
	}

	buf := make([]byte, size)
	ret, _, _ := pmGetExtendedTcpTableProc.Call(
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0, pmAF_INET, pmTCP_TABLE_OWNER_PID_ALL, 0)
	if ret != 0 {
		return nil, fmt.Errorf("GetExtendedTcpTable failed: %d", ret)
	}

	numEntries := binary.LittleEndian.Uint32(buf[:4])
	rows := make([]pmMIB_TCPROW_OWNER_PID, numEntries)
	for i := uint32(0); i < numEntries; i++ {
		offset := 4 + i*24
		rows[i] = pmMIB_TCPROW_OWNER_PID{
			DwState:      binary.LittleEndian.Uint32(buf[offset:]),
			DwLocalAddr:  binary.LittleEndian.Uint32(buf[offset+4:]),
			DwLocalPort:  binary.LittleEndian.Uint32(buf[offset+8:]),
			DwRemoteAddr: binary.LittleEndian.Uint32(buf[offset+12:]),
			DwRemotePort: binary.LittleEndian.Uint32(buf[offset+16:]),
			DwOwningPid:  binary.LittleEndian.Uint32(buf[offset+20:]),
		}
	}
	return rows, nil
}

func pmPortFromInt(n uint32) uint16 {
	return uint16(n)<<8 | uint16(n>>8)
}

// FindProcessByPort returns the PID occupying the specified port using Windows API directly.
func FindProcessByPort(port int) (int, error) {
	if runtime.GOOS != "windows" {
		return 0, fmt.Errorf("only supported on windows")
	}

	if time.Since(pmLastProcEnum) > 15*time.Second {
		pmEnumerateProcesses()
		pmLastProcEnum = time.Now()
	}

	rows, err := pmGetTcpTable()
	if err != nil {
		return 0, err
	}

	targetPort := uint16(port)
	for _, row := range rows {
		localPort := pmPortFromInt(row.DwLocalPort)
		if localPort == targetPort && row.DwOwningPid > 0 {
			return int(row.DwOwningPid), nil
		}
		remotePort := pmPortFromInt(row.DwRemotePort)
		if remotePort == targetPort && row.DwOwningPid > 0 {
			return int(row.DwOwningPid), nil
		}
	}
	return 0, nil
}

// GetProcessNameByPID gets the process name for the given PID.
func GetProcessNameByPID(pid int) (string, error) {
	if runtime.GOOS != "windows" {
		return "", fmt.Errorf("only supported on windows")
	}

	name := pmGetProcessName(uint32(pid))
	if name == "" {
		// Try to enumerate all processes and find it
		pmEnumerateProcesses()
		pmProcNameMu.Lock()
		name = pmProcNameCache[uint32(pid)]
		pmProcNameMu.Unlock()
	}
	if name == "" {
		return "", fmt.Errorf("process not found")
	}
	return name, nil
}

// KillProcessByPID forcefully terminates the specified PID and its child processes.
func KillProcessByPID(pid int) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("only supported on windows")
	}
	// Use taskkill with HideWindow - this is the standard Windows way
	cmd := exec.Command("taskkill", "/F", "/T", "/PID", fmt.Sprintf("%d", pid))
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.Run()
}

// EnsurePortAvailable checks port availability:
// 1. If occupied by processes in selfNames list, try Kill.
// 2. If occupied by other processes or Kill fails, find next available port.
func EnsurePortAvailable(startPort int, selfNames []string) (int, error) {
	currentPort := startPort
	maxAttempts := 10

	for i := 0; i < maxAttempts; i++ {
		pid, err := FindProcessByPort(currentPort)
		if err != nil || pid == 0 {
			ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", currentPort))
			if err == nil {
				ln.Close()
				return currentPort, nil
			}
		} else {
			name, _ := GetProcessNameByPID(pid)
			isSelf := false
			for _, self := range selfNames {
				if strings.EqualFold(name, self) || strings.EqualFold(name, self+".exe") {
					isSelf = true
					break
				}
			}

			if isSelf {
				if err := KillProcessByPID(pid); err == nil {
					return currentPort, nil
				}
			}
		}

		currentPort++
	}

	return startPort, fmt.Errorf("could not find available port after %d attempts", maxAttempts)
}
