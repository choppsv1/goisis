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
