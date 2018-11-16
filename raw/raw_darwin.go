// -*- coding: utf-8 -*-
//
// November 9 2018, Christian Hopps <chopps@gmail.com>
//

package raw

import (
	"fmt"
	// "github.com/choppsv1/goisis/pkt"
	"golang.org/x/net/bpf"
	"net"
	"syscall"
	"unsafe"
)

// Constants not found elsewhere
const (
	IFNAMSIZ = 16 // Max interface name length
)

type EtherHeader struct {
}

// struct frame_t {
// struct ether_header header;
// unsigned char payload[syscall.ETHER_MAX_LEN - syscall.ETHER_HDR_LEN];
// ssize_t len;
// ssize_t payload_len;
// }

type ifreq struct {
	name [IFNAMSIZ]byte
	data uintptr
}

// WritePacket writes an L2 frame to the interface
func (sock IntfSocket) WritePacket(pkt []byte, to net.HardwareAddr) (int, error) {
	// addr := &syscall.SockaddrLinklayer{
	// 	Ifindex: sock.intf.Index,
	// 	Halen:   uint8(len(to)),
	// }
	// copy(addr.Addr[:], to)
	// n, err := syscall.SendmsgN(sock.fd, pkt, nil, addr, 0)
	// return n, err
	return 0, nil
}

// WriteEtherPacket writes an Ethernet frame to the interface
func (sock IntfSocket) WriteEtherPacket(pkt []byte) (int, error) {
	// addr := &syscall.SockaddrLinklayer{
	// 	Halen: 6,
	// }
	// copy(addr.Addr[:], pkt[0:6])
	// n, err := syscall.SendmsgN(sock.fd, pkt, nil, addr, 0)
	// return n, err
	return 0, nil
}

func openBPF() (int, error) {
	var fd int
	var err error
	for i := 0; i < 255; i++ {
		bpfname := fmt.Sprintf("/dev/bpf%d", i)
		fd, err = syscall.Open(bpfname, syscall.O_RDWR, 0770)
		if err == nil {
			return fd, err
		}
		if err != syscall.EBUSY {
			return -1, err
		}
	}
	return -1, syscall.ENODEV
}

func fdioctl(fd int, ctl uintptr, args uintptr) error {
	_, _, err := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), ctl, args)
	return err
}

// NewInterfaceSocket open a new raw socket to the given interface
func NewInterfaceSocket(ifname string) (IntfSocket, error) {
	var rv IntfSocket
	var err error

	rv.fd, err = openBPF()
	if err != nil {
		return rv, err
	}

	// rv.fd, err = syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	// if err != nil {
	// 	return rv, err
	// }

	rv.intf, err = net.InterfaceByName(ifname)
	if err != nil {
		return rv, err
	}

	var iv ifreq
	copy(iv.name[:], []byte(ifname))
	ivp := uintptr(unsafe.Pointer(&iv))
	enable := 1
	enablep := uintptr(unsafe.Pointer(&enable))

	if err = fdioctl(rv.fd, syscall.BIOCSETIF, ivp); err != nil {
		return rv, err
	}
	if err = fdioctl(rv.fd, syscall.BIOCGHDRCMPLT, enablep); err != nil {
		return rv, err
	}
	if err = fdioctl(rv.fd, syscall.BIOCSSEESENT, enablep); err != nil {
		return rv, err
	}
	if err = fdioctl(rv.fd, syscall.BIOCIMMEDIATE, enablep); err != nil {
		return rv, err
	}
	return rv, nil
}

// SetBPF filter on the interface socket
func (sock IntfSocket) SetBPF(filter []bpf.RawInstruction) error {
	prog := syscall.SockFprog{
		Len:    uint32(len(filter)),
		Filter: (*syscall.SockFilter)(unsafe.Pointer(&filter[0])),
	}
	if err = fdioctl(rv.fd, syscall.BIOCSETF, uintptr(unsafe.Pointer(&prog))); err != nil {
		return err
	}
	return nil
}
