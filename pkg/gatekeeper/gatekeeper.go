package gatekeeper

import (
	"fmt"
)

type Gatekeeper struct {
	TargetIP string
	Port     int
}

func New(targetIP string, port int) *Gatekeeper {
	if port == 0 {
		port = 389
	}
	return &Gatekeeper{
		TargetIP: targetIP,
		Port:     port,
	}
}

func (g *Gatekeeper) Validate() error {
	if err := g.CheckRFC1918(); err != nil {
		return fmt.Errorf("RFC1918 violation: %w", err)
	}
	if err := g.CheckSubnet(); err != nil {
		return fmt.Errorf("subnet mismatch: %w", err)
	}
	if err := g.CheckARP(); err != nil {
		return fmt.Errorf("L2 ARP check failed: %w", err)
	}
	if err := g.CheckTTL(); err != nil {
		return fmt.Errorf("TTL hop check failed: %w", err)
	}
	return nil
}
