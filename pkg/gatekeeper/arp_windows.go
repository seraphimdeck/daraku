//go:build windows

package gatekeeper

import (
	"fmt"
	"net"
	"unsafe"
	"golang.org/x/sys/windows"
)

func (g *Gatekeeper) CheckARP() error {
	var table *windows.MIB_IPNET_TABLE2
	
	err := windows.GetIpNetTable2(windows.AF_INET, &table)
	if err != nil {
		return fmt.Errorf("gagal mengeksekusi GetIpNetTable2: %w", err)
	}
	defer windows.FreeMibTable(table)

	targetIP := net.ParseIP(g.TargetIP)
	if targetIP == nil {
		return fmt.Errorf("alamat IP target tidak valid: %s", g.TargetIP)
	}

	found := false
	rows := unsafe.Slice(&table.Table[0], table.NumEntries)

	for _, row := range rows {
		addr := (*windows.RawSockaddrInet4)(unsafe.Pointer(&row.Address))
		ip := net.IPv4(addr.Addr[0], addr.Addr[1], addr.Addr[2], addr.Addr[3])

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

	if !found {
		return fmt.Errorf("target IP %s tidak ditemukan pada tabel ARP L2 lokal", g.TargetIP)
	}

	return nil
}
