// -*- coding: utf-8 -*-
//
// November 9 2018, Christian Hopps <chopps@gmail.com>
//
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

// Use go's OS independent functionality for doing this.
// func GetInterfacePrefix(ifname string) (net.IP, net.IPNet) {
// 	out, err := exec.Command("/sbin/ifconfig", ifname).Output()
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	// re := regexp.MustCompile("(?:HWaddr|ether) ([a-zA-Z0-9:]+)")
// 	// match := re.FindSubmatch(out)
// 	// assert match
// 	// mac_addr = clns.mac_encode(match.group(1))

// 	// # inet addr:192.168.1.10  Bcast:192.168.1.255  Mask:255.255.255.0
// 	re := regexp.MustCompile("inet (?:addr:)?([0-9.]+).*(?:Mask:|netmask )([0-9.]+)")
// 	match := re.FindSubmatch(out)
// 	if len(match) < 2 {
// 		log.Fatal("ERROR: No IPv4 address found for %s", ifname)
// 	}
// 	cidrstr := fmt.Sprintf("%s/%s", match[1], match[2])
// 	addr, net, err := net.ParseCIDR(cidrstr)
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	if net == nil {
// 		log.Fatal("ERROR: No IPv4 netmask found for %s", ifname)
// 	}
// 	return addr, *net

// 	// # mask = ipaddress.ip_address(match.group(2))
// 	/// ipv4_prefix = ipaddress.ip_interface('{}/{}'.format(*match.groups()))
// 	// # ipv4_prefix = ipaddress.ip_interface('{}/24'.format(match.group(1)))
// 	// # ipv4_prefix = ipaddress.ip_interface('{}/24'.format(match.group(1)))
// 	// return mac_addr, ipv4_prefix
// }
