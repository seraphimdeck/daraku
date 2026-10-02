package gatekeeper

import (
	"fmt"
	"net"
	"strconv"
	"syscall"
	"time"
)

func (g *Gatekeeper) CheckTTL() error {
	address := net.JoinHostPort(g.TargetIP, strconv.Itoa(g.Port))

	var controlErr error

	dialer := net.Dialer{
		Timeout: 2 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				err := syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL, 1)
				if err != nil {
					controlErr = fmt.Errorf("gagal mengkonfigurasi IP_TTL=1: %w", err)
				}
			})
		},
	}

	conn, err := dialer.Dial("tcp", address)
	if err != nil {
		if controlErr != nil {
			return controlErr
		}
		return fmt.Errorf("probe TTL=1 gagal ke %s: target berada di luar jaringan lokal (terdeteksi router hop)", address)
	}
	defer conn.Close()

	return nil
}
