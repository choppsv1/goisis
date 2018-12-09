// -*- coding: utf-8 -*-
//
// November 9 2018, Christian Hopps <chopps@gmail.com>
//
package raw

import (
	"golang.org/x/net/bpf"
	"net"
	"syscall"
	"unsafe"
)

// ReadPacket from the interface
func (sock IntfSocket) ReadPacket() ([]byte, syscall.Sockaddr, error) {
	n, _, _, from, err := syscall.Recvmsg(sock.fd, nil, nil, syscall.MSG_PEEK|syscall.MSG_TRUNC)
	if err != nil {
		return nil, nil, err
	}

	b := make([]byte, n)
	n, _, _, from, err = syscall.Recvmsg(sock.fd, b, nil, 0)
	return b, from, err
}

// WritePacket writes an L2 frame to the interface
func (sock IntfSocket) WritePacket(pkt []byte, to net.HardwareAddr) (int, error) {
	addr := &syscall.SockaddrLinklayer{
		Ifindex: sock.intf.Index,
		Halen:   uint8(len(to)),
	}
	copy(addr.Addr[:], to)
	n, err := syscall.SendmsgN(sock.fd, pkt, nil, addr, 0)
	return n, err
}

// WriteEtherPacket writes an Ethernet frame to the interface
func (sock IntfSocket) WriteEtherPacket(pkt []byte) (int, error) {
	addr := &syscall.SockaddrLinklayer{
		Halen: 6,
	}
	copy(addr.Addr[:], pkt[0:6])
	n, err := syscall.SendmsgN(sock.fd, pkt, nil, addr, 0)
	return n, err
}

// NewInterfaceSocket open a new raw socket to the given interface
func NewInterfaceSocket(ifname string) (IntfSocket, error) {
	var rv IntfSocket
	var err error

	rv.fd, err = syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		return rv, err
	}

	rv.intf, err = net.InterfaceByName(ifname)
	if err != nil {
		return rv, err
	}

	ll := syscall.SockaddrLinklayer{
		Ifindex: rv.intf.Index,
	}
	err = syscall.Bind(rv.fd, &ll)
	if err != nil {
		return rv, err
	}
	return rv, nil
}

// SetBPF filter on the interface socket
func (sock IntfSocket) SetBPF(filter []bpf.RawInstruction) error {
	prog := syscall.SockFprog{
		Len:    uint16(len(filter)),
		Filter: (*syscall.SockFilter)(unsafe.Pointer(&filter[0])),
	}
	_, _, err := syscall.Syscall6(syscall.SYS_SETSOCKOPT, uintptr(sock.fd),
		uintptr(syscall.SOL_SOCKET),
		uintptr(syscall.SO_ATTACH_FILTER),
		uintptr(unsafe.Pointer(&prog)),
		uintptr(unsafe.Sizeof(prog)),
		0)
	if err != 0 {
		return syscall.Errno(err)
	}
	return nil
}
