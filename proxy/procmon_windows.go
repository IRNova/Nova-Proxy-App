//go:build windows

package proxy

import (
	"encoding/binary"
	"fmt"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"
)

var (
	modiphlpapi = syscall.NewLazyDLL("iphlpapi.dll")
	procGetExtendedTcpTable = modiphlpapi.NewProc("GetExtendedTcpTable")

	modkernel32 = syscall.NewLazyDLL("kernel32.dll")
	procCreateToolhelp32Snapshot = modkernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32First          = modkernel32.NewProc("Process32FirstW")
	procProcess32Next           = modkernel32.NewProc("Process32NextW")
	procOpenProcess             = modkernel32.NewProc("OpenProcess")
	procCloseHandle             = modkernel32.NewProc("CloseHandle")

	modpsapi            = syscall.NewLazyDLL("psapi.dll")
	procGetModuleBaseName = modpsapi.NewProc("GetModuleBaseNameW")
)

const (
	AF_INET                        = 2
	TCP_TABLE_OWNER_PID_ALL        = 5
	TH32CS_SNAPPROCESS             = 0x00000002
	PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
	PROCESS_VM_READ                = 0x0010
)

type MIB_TCPROW_OWNER_PID struct {
	DwState      uint32
	DwLocalAddr  uint32
	DwLocalPort  uint32
	DwRemoteAddr uint32
	DwRemotePort uint32
	DwOwningPid  uint32
}

type PROCESSENTRY32W struct {
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
	procNameMu   sync.Mutex
	procNameCache = map[uint32]string{}
	lastProcEnum  = time.Now()
)

func getProcessName(pid uint32) string {
	procNameMu.Lock()
	defer procNameMu.Unlock()

	if name, ok := procNameCache[pid]; ok {
		return name
	}

	handle, _, _ := procOpenProcess.Call(PROCESS_QUERY_LIMITED_INFORMATION|PROCESS_VM_READ, 0, uintptr(pid))
	if handle == 0 {
		return ""
	}
	defer procCloseHandle.Call(handle)

	var buf [260]uint16
	ret, _, _ := procGetModuleBaseName.Call(handle, 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if ret == 0 {
		return ""
	}
	length := 0
	for buf[length] != 0 {
		length++
	}
	name := strings.ToLower(string(utf16.Decode(buf[:length])))
	if name != "" {
		procNameCache[pid] = name
	}
	return name
}

func enumerateProcesses() {
	snapshot, _, _ := procCreateToolhelp32Snapshot.Call(TH32CS_SNAPPROCESS, 0)
	if snapshot == uintptr(syscall.InvalidHandle) {
		return
	}
	defer procCloseHandle.Call(snapshot)

	activePids := make(map[int32]bool)
	var pe PROCESSENTRY32W
	pe.DwSize = uint32(unsafe.Sizeof(pe))

	ret, _, _ := procProcess32First.Call(snapshot, uintptr(unsafe.Pointer(&pe)))
	for ret != 0 {
		pid := pe.Th32ProcessID
		name := strings.ToLower(syscall.UTF16ToString(pe.SzExeFile[:]))
		if _, exists := procNameCache[pid]; !exists {
			procNameCache[pid] = name
		}
		activePids[int32(pid)] = true
		ret, _, _ = procProcess32Next.Call(snapshot, uintptr(unsafe.Pointer(&pe)))
	}

	// Clean up stale cache entries (PIDs no longer running)
	for pid := range procNameCache {
		if !activePids[int32(pid)] {
			delete(procNameCache, pid)
		}
	}
}

func getExtendedTcpTable() ([]MIB_TCPROW_OWNER_PID, error) {
	var size uint32
	procGetExtendedTcpTable.Call(0, uintptr(unsafe.Pointer(&size)), 0, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)
	if size == 0 {
		return nil, fmt.Errorf("failed to get table size")
	}

	buf := make([]byte, size)
	ret, _, _ := procGetExtendedTcpTable.Call(
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)
	if ret != 0 {
		return nil, fmt.Errorf("GetExtendedTcpTable failed: %d", ret)
	}

	numEntries := binary.LittleEndian.Uint32(buf[:4])
	rows := make([]MIB_TCPROW_OWNER_PID, numEntries)
	for i := uint32(0); i < numEntries; i++ {
		offset := 4 + i*24
		rows[i] = MIB_TCPROW_OWNER_PID{
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

func portFromInt(n uint32) uint16 {
	return uint16(n)<<8 | uint16(n>>8)
}

func newTCPFetcher(proxyPort int) func() (map[string]int32, error) {
	return func() (map[string]int32, error) {
		if time.Since(lastProcEnum) > 15*time.Second {
			enumerateProcesses()
			lastProcEnum = time.Now()
		}

		rows, err := getExtendedTcpTable()
		if err != nil {
			return nil, err
		}

		result := make(map[string]int32)
		for _, row := range rows {
			localPort := portFromInt(row.DwLocalPort)
			remotePort := portFromInt(row.DwRemotePort)

			if int(remotePort) == proxyPort {
				pid := int32(row.DwOwningPid)
				if pid > 0 {
					portKey := fmt.Sprintf("%d", localPort)
					result[portKey] = pid
				}
			}
		}
		return result, nil
	}
}

// getAllProcessPIDs returns all cached process PIDs (enumerated from system).
func getAllProcessPIDs() []int32 {
	procNameMu.Lock()
	defer procNameMu.Unlock()
	pids := make([]int32, 0, len(procNameCache))
	for pid := range procNameCache {
		pids = append(pids, int32(pid))
	}
	return pids
}


