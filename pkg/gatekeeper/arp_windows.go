//go:build windows
// +build windows

package gatekeeper

import (
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

var (
	iphlpapi           = syscall.NewLazyDLL("iphlpapi.dll")
	procGetIpNetTable2 = iphlpapi.NewProc("GetIpNetTable2")
	procFreeMibTable   = iphlpapi.NewProc("FreeMibTable")
)

type MIB_IP_ROW_ADDRESS struct {
	Family uint16
	Data   [24]byte
}

type MIB_IPNET_ROW2 struct {
	Address               MIB_IP_ROW_ADDRESS
	InterfaceIndex        uint32
	InterfaceLuid         uint64
	PhysicalAddress       [8]byte
	PhysicalAddressLength uint32
	State                 uint32
	Flags                 uint32
	ReachabilityTime      uint32
}

type MIB_IPNET_TABLE2 struct {
	NumEntries uint32
	Table      [1]MIB_IPNET_ROW2
}

func (g *Gatekeeper) CheckARP() error {
	var table *MIB_IPNET_TABLE2

	r1, _, _ := procGetIpNetTable2.Call(
		uintptr(2),
		uintptr(unsafe.Pointer(&table)),
	)

	if r1 != 0 {
		return fmt.Errorf("gagal mengeksekusi GetIpNetTable2, kode error: %v", r1)
	}
	if table != nil {
		defer procFreeMibTable.Call(uintptr(unsafe.Pointer(table)))
	}

	targetIP := net.ParseIP(g.TargetIP)
	if targetIP == nil {
		return fmt.Errorf("alamat IP target tidak valid: %s", g.TargetIP)
	}

	found := false
	if table != nil && table.NumEntries > 0 {
		rows := unsafe.Slice(&table.Table[0], int(table.NumEntries))

		for _, row := range rows {
			rawIP := row.Address.Data[2:6]
			ip := net.IPv4(rawIP[0], rawIP[1], rawIP[2], rawIP[3])

			if ip.Equal(targetIP) {
				isEmpty := true
				for i := uint32(0); i < row.PhysicalAddressLength; i++ {
					if row.PhysicalAddress[i] != 0 {
						isEmpty = false
						break
					}
				}

				if !isEmpty {
					found = true
					break
				}
			}
		}
	}

	if !found {
		return fmt.Errorf("target IP %s tidak ditemukan pada tabel ARP L2 lokal", g.TargetIP)
	}

	return nil
}
