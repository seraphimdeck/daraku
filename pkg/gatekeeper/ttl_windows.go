//go:build windows
// +build windows
package gatekeeper

import "syscall"

func setIPTLSocketOption(fd uintptr) error {
	return syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IP, syscall.IP_TTL, 1)
}
