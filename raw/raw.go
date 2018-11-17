// +build darwin freebsd netbsd openbsd

package raw

import (
	"net"
)

// IntfSocket is an interface socket connection
type IntfSocket struct {
	fd   int
	intf *net.Interface
}

func htons(val uint16) uint16 {
	return (val&0x00FF)<<8 | (val&0xFF00)>>8
}

func ntohs(val uint16) uint16 {
	return htons(val)
}

func htonl(val uint32) uint32 {
	return (val&0x000000FF)<<24 | (val&0x0000FF00)<<8 | (val&0x00FF0000)>>8 | (val&0xFF000000)>>24
}

func ntohl(val uint32) uint32 {
	return htonl(val)
}
