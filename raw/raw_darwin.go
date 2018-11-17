// -*- coding: utf-8 -*-
//
// November 9 2018, Christian Hopps <chopps@gmail.com>
//

package raw

import (
	"errors"
	"fmt"
	"github.com/choppsv1/goisis/pkt"
	"golang.org/x/net/bpf"
	"net"
	"os"
	"syscall"
	"unsafe"
)

type bpf_timeval struct {
	tv_sec  int32
	tv_usec int32
}

var (
	ErrShortFrame = errors.New("BPF: Short frame received")
)

// #include <net/bpf.h>: struct bpf_hdr
const (
	BPFH_TSTAMP_SEC  = iota
	BPFH_TSTAMP_USEC = BPFH_TSTAMP_SEC + 4
	BPFH_CAPLEN      = BPFH_TSTAMP_USEC + 4
	BPFH_DATALEN     = BPFH_CAPLEN + 4
	BPFH_HDRLEN      = BPFH_DATALEN + 4
	BPFH_MINSIZE     = BPFH_HDRLEN + 2
)

//  #include <net/bpf.h>: struct bpf_program
type SockFprog struct {
	Len    uint32
	Filter *bpf.RawInstruction
}

// Constants not found elsewhere
const (
	IFNAMSIZ   = 16 // Max interface name length
	MAXBUFSIZE = 1518 + BPFH_MINSIZE + 2
)

// ifreq
type ivalue struct {
	name  [IFNAMSIZ]byte
	value int16
}

// ReadPacket from the interface
func (sock IntfSocket) ReadPacket() ([]byte, syscall.Sockaddr, error) {
	b := make([]byte, MAXBUFSIZE)
	n, err := syscall.Read(sock.fd, b)
	if err != nil {
		return nil, nil, err
	}
	if n < BPFH_MINSIZE {
		return nil, nil, ErrShortFrame
	}
	caplen := ntohl(pkt.GetUInt32(b[BPFH_CAPLEN:]))
	datalen := ntohl(pkt.GetUInt32(b[BPFH_DATALEN:]))
	bhlen := int(ntohs(pkt.GetUInt16(b[BPFH_HDRLEN:])))
	if n < bhlen || caplen < datalen {
		return nil, nil, ErrShortFrame
	}
	return b[bhlen:n], nil, nil
}

// WritePacket writes an L2 frame to the interface
func (sock IntfSocket) WritePacket(pkt []byte, to net.HardwareAddr) (int, error) {
	return syscall.Write(sock.fd, pkt)
}

// WriteEtherPacket writes an Ethernet frame to the interface
func (sock IntfSocket) WriteEtherPacket(pkt []byte) (int, error) {
	return syscall.Write(sock.fd, pkt)
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

	// This must be done before BIOCSETIF
	ival = MAXBUFSIZE
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
		Filter: &filter[0],
	}
	if err := fdioctl(sock.fd, syscall.BIOCSETF, uintptr(unsafe.Pointer(&prog))); err != nil {
		fmt.Fprintf(os.Stderr, "Error BIOCSETF: %s\n", err)
		return err
	}
	return nil
}
