//go:build windows
// +build windows

package gatekeeper

import "fmt"

func (g *Gatekeeper) CheckARP() error {
	fmt.Printf("[INFO] ARP L2 check tidak tersedia di platform Windows, dilewati.\n")
	return nil
}