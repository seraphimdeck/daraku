//go:build linux

package gatekeeper

import "syscall"

func setIPTLSocketOption(fd uintptr) error {
	return syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL, 1)
}
