package main

import (
	"flag"
	"fmt"
	"github.com/choppsv1/goisis/clns"
	"net"
	"os"
	"strings"
)

// GlbSystemID is the system ID of this IS-IS instance
var GlbSystemID net.HardwareAddr

// GlbAreaID is the area this IS-IS instance is in.
var GlbAreaID []byte

// GlbNLPID holds an array of the NLPID that we support
// var GlbNLPID = []byte{clns.NLPIDIPv4}
var GlbNLPID = []byte{clns.NLPIDIPv4, clns.NLPIDIPv6}

// GlbDebug are the enable debug.
var GlbDebug = DbgFPkt | DbgFAdj | DbgFDIS

// var GlbDebug DbgFlag

func main() {
	var err error

	// areaIDPtr := flag.String("areaid", "00", "area id of this instance")
	iflistPtr := flag.String("iflist", "", "Space separated list of interfaces to run on")
	playPtr := flag.Bool("play", false, "run the playground")
	sysIDPtr := flag.String("sysid", "0000.0000.0001", "system id of this instance")
	flag.Parse()

	if *playPtr {
		playground()
		return
	}

	GlbSystemID, err = clns.ISODecode(*sysIDPtr)

	// XXX eventually support custom areas
	GlbAreaID = make([]byte, 1)
	GlbAreaID[0] = 0x00

	linkdb := NewLinkDB()
	quit := make(chan bool)

	// Get interfaces to run on.
	fmt.Printf("%v: %q\n", iflistPtr, *iflistPtr)
	for _, ifname := range strings.Fields(*iflistPtr) {
		fmt.Printf("Adding LAN link: %q\n", ifname)
		var lanlink *CircuitLAN
		lanlink, err = NewLANCircuit(ifname, linkdb.inpkts, quit, 1)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating link: %s", err)
			os.Exit(1)
		}
		linkdb.links[ifname] = lanlink
	}

	processPackets(linkdb)
	close(quit)
}

// -----------------------------------------------------------------------------
// processPackets handles all incoming packets (frames) serially. If performance
// is an issue we could parallelize this based on packet type etc..
// -----------------------------------------------------------------------------
func processPackets(linkdb *LinkDB) {
	for {
		select {
		case pdu := <-linkdb.inpkts:
			err := pdu.link.ProcessPDU(pdu)
			if err != nil {
				debug(DbgFPkt, "Error processing packet: %s\n", err)
			}
		}
	}
}
