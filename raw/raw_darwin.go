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
	"os"
	"syscall"
	"unsafe"
)

// Constants not found elsewhere
const (
	IFNAMSIZ   = 16 // Max interface name length
	MAXBUFSIZE = 1518
)

type EtherHeader struct {
}

// struct frame_t {
// struct ether_header header;
// unsigned char payload[syscall.ETHER_MAX_LEN - syscall.ETHER_HDR_LEN];
// ssize_t len;
// ssize_t payload_len;
// }

type ivalue struct {
	name  [IFNAMSIZ]byte
	value int16
}

type SockFilter struct {
	Code uint16 // Actual filter code.
	JT   uint8  // Jump true.
	JF   uint8  // Jump false.
	K    uint32 // Generic multiuse field.
}

type SockFprog struct {
	Len    uint32
	Filter *SockFilter
}

// ReadPacket from the interface
func (sock IntfSocket) ReadPacket() ([]byte, syscall.Sockaddr, error) {
	b := make([]byte, MAXBUFSIZE)
	//sys	Read(fd int, p []byte) (n int, err error)
	n, err := syscall.Read(sock.fd, b)
	fmt.Fprintf(os.Stderr, "INFO: ReadPacket len %d\n", n)
	return b, nil, err
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
	n, err := syscall.Write(sock.fd, pkt)
	fmt.Fprintf(os.Stderr, "INFO: WritePacket to %s n %d err %s\n", to, n, err)
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
	fmt.Fprintf(os.Stderr, "INFO: WriteEtherPacket\n")
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
	if err != 0 {
		return syscall.Errno(err)
	}
	return nil
}

// NewInterfaceSocket open a new raw socket to the given interface
func NewInterfaceSocket(ifname string) (IntfSocket, error) {
	var rv IntfSocket
	var err error
	var ival int
	ivalp := uintptr(unsafe.Pointer(&ival))

	rv.fd, err = openBPF()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error openBPF: %s\n", err)
		return rv, err
	}

	// This must be done before SETIF
	ival = 1518
	if err = fdioctl(rv.fd, syscall.BIOCSBLEN, ivalp); err != nil {
		fmt.Fprintf(os.Stderr, "Error BIOCSBLEN: %s\n", err)
		return rv, err
	}

	rv.intf, err = net.InterfaceByName(ifname)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error InterfaceByName: %s\n", err)
		return rv, err
	}

	var iv ivalue
	copy(iv.name[:], []byte(ifname))
	if err = fdioctl(rv.fd, syscall.BIOCSETIF, uintptr(unsafe.Pointer(&iv))); err != nil {
		fmt.Fprintf(os.Stderr, "Error BIOCSETIF: %s\n", err)
		return rv, err
	}

	ival = 1
	if err = fdioctl(rv.fd, syscall.BIOCGHDRCMPLT, ivalp); err != nil {
		fmt.Fprintf(os.Stderr, "Error BIOCGHDRCMPLT: %s\n", err)
		return rv, err
	}
	if err = fdioctl(rv.fd, syscall.BIOCIMMEDIATE, ivalp); err != nil {
		fmt.Fprintf(os.Stderr, "Error BIOCIMMEDIATE: %s\n", err)
		return rv, err
	}

	ival = 0
	if err = fdioctl(rv.fd, syscall.BIOCSSEESENT, ivalp); err != nil {
		fmt.Fprintf(os.Stderr, "Error BIOCSSEESENT: %s\n", err)
		return rv, err
	}
	return rv, nil
}

// SetBPF filter on the interface socket
func (sock IntfSocket) SetBPF(filter []bpf.RawInstruction) error {
	prog := SockFprog{
		Len:    uint32(len(filter)),
		Filter: (*SockFilter)(unsafe.Pointer(&filter[0])),
	}
	if err := fdioctl(sock.fd, syscall.BIOCSETF, uintptr(unsafe.Pointer(&prog))); err != nil {
		fmt.Fprintf(os.Stderr, "Error BIOCSETF: %s\n", err)
		return err
	}
	return nil
}
