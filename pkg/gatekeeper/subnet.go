package gatekeeper

import (
	"fmt"
	"net"
)

func (g *Gatekeeper) CheckSubnet() error {
	targetIP := net.ParseIP(g.TargetIP)
	if targetIP == nil {
		return fmt.Errorf("alamat IP target tidak valid: %s", g.TargetIP)
	}

	interfaces, err := net.Interfaces()
	if err != nil {
		return fmt.Errorf("gagal mengambil daftar antarmuka jaringan lokal: %w", err)
	}

	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}

			if ipNet.Contains(targetIP) {
				return nil
			}
		}
	}

	return fmt.Errorf("IP target %s tidak berada dalam subnet lokal mana pun", g.TargetIP)
}
