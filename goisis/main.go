package main

import (
	"flag"
	"fmt"
	"github.com/choppsv1/goisis/clns"
	"github.com/choppsv1/goisis/ether"
	"net"
	"os"
	"strings"
)

func processPackets(linkdb *LinkDB) {
	for {
		select {
		case frame := <-linkdb.inpkts:
			debug.Printf(" <- len %d from link %s to %s from %s llclen %d\n",
				len(frame.pkt),
				frame.link.(*LANLink).intf.Name,
				ether.Frame(frame.pkt).GetEtherDest(),
				ether.Frame(frame.pkt).GetEtherSrc(),
				ether.Frame(frame.pkt).GetEtherTypeLen())

			err := frame.link.ProcessPacket(frame)
			if err != nil {
				debug.Printf("Got error processing packet: %s\n", err)
			}
		}
	}
}

// SystemID is the system ID of this IS-IS instance
var SystemID net.HardwareAddr

// AreaID is the area this IS-IS instance is in.
var AreaID []byte

// NLPID holds an array of the NLPID that we support
// var NLPID = []byte{clns.NLPIDIPv4, clns.NLPIDIPv6}
var NLPID = []byte{clns.NLPIDIPv4}

func main() {
	var err error

	// areaIDPtr := flag.String("areaid", "00", "area id of this instance")
	iflistPtr := flag.String("iflist", "", "Space separated list of interfaces to run on")
	playPtr := flag.Bool("play", false, "run the playground")
	sysIDPtr := flag.String("sysid", "00:00:00:00:00:01", "system id of this instance")
	flag.Parse()

	if *playPtr {
		playground()
		return
	}

	linkdb := NewLinkDB()
	quit := make(chan bool)
	SystemID, err = net.ParseMAC(*sysIDPtr)

	// XXX eventually support custom areas
	AreaID = make([]byte, 1)
	AreaID[0] = 0x00

	// Get interfaces to run on.
	fmt.Printf("%v: %q\n", iflistPtr, *iflistPtr)
	for _, ifname := range strings.Fields(*iflistPtr) {
		fmt.Printf("Adding LAN link: %q\n", ifname)
		var lanlink *LANLink
		lanlink, err = NewLANLink(ifname, linkdb.inpkts, quit, 1)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating link: %s", err)
			os.Exit(1)
		}
		linkdb.links[ifname] = lanlink
	}

	processPackets(linkdb)
	close(quit)
}
