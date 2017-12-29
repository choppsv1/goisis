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

// GlbCDB is the global circuit DB for this instance
var GlbCDB = NewCircuitDB()

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

	GlbSystemID, err = clns.ISOEncode(*sysIDPtr)

	// XXX eventually support custom areas
	GlbAreaID = make([]byte, 1)
	GlbAreaID[0] = 0x00

	quit := make(chan bool)

	// Get interfaces to run on.
	fmt.Printf("%v: %q\n", iflistPtr, *iflistPtr)
	for _, ifname := range strings.Fields(*iflistPtr) {
		fmt.Printf("Adding LAN link: %q\n", ifname)
		var lanlink *CircuitLAN
		lanlink, err = NewCircuitLAN(ifname, GlbCDB.inpkts, quit, 1)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating link: %s", err)
			os.Exit(1)
		}
		GlbCDB.links[ifname] = lanlink
	}

	processPDUs(GlbCDB)
	close(quit)
}
