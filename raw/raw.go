// +build darwin freebsd netbsd openbsd

package raw

import (
	"net"
	"syscall"
)

// IntfSocket is an interface socket connection
type IntfSocket struct {
	fd   int
	intf *net.Interface
}

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

func htons(val uint16) uint16 {
	return (val&0x00FF)<<8 | (val&0xFF00)>>8
}
