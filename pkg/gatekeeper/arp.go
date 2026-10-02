package gatekeeper

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func (g *Gatekeeper) CheckARP() error {
	file, err := os.Open("/proc/net/arp")
	if err != nil {
		return nil
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	if scanner.Scan() {
		_ = scanner.Text()
	}

	found := false
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 4 {
			ip := fields[0]
			mac := fields[3]

			if ip == g.TargetIP {
				if mac != "00:00:00:00:00:00" && mac != "00-00-00-00-00-00" {
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
