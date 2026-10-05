//go:build linux

package gatekeeper

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
)

func (g *Gatekeeper) CheckARP() error {
	file, err := os.Open("/proc/net/arp")
	if err != nil {
		return fmt.Errorf("gagal membuka tabel ARP di /proc/net/arp (apakah Anda menjalankan ini di macOS?): %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	if scanner.Scan() {
		_ = scanner.Text()
	}

	targetIP := net.ParseIP(g.TargetIP)
	if targetIP == nil {
		return fmt.Errorf("alamat IP target tidak valid: %s", g.TargetIP)
	}

	found := false
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 4 {
			ipStr := fields[0]
			mac := fields[3]
			parsedIP := net.ParseIP(ipStr)
			if parsedIP != nil && parsedIP.Equal(targetIP) {
				if mac != "00:00:00:00:00:00" && mac != "00-00-00-00-00-00" {
					found = true
					break
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("terjadi kesalahan saat membaca file arp: %w", err)
	}

	if !found {
		return fmt.Errorf("target IP %s tidak ditemukan pada tabel ARP L2 lokal", g.TargetIP)
	}

	return nil
}
