package gatekeeper

import (
	"fmt"
	"net"
)

func (g *Gatekeeper) CheckRFC1918() error {
	ip := net.ParseIP(g.TargetIP)
	if ip == nil {
		return fmt.Errorf("alamat IP target tidak valid: %s", g.TargetIP)
	}

	privateCIDRs := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
	}

	for _, cidr := range privateCIDRs {
		_, block, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if block.Contains(ip) {
			return nil
		}
	}

	return fmt.Errorf("alamat IP %s bukan IP privat", g.TargetIP)
}
