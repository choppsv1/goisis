package main

import (
	"flag"
	"fmt"
	"github.com/choppsv1/goisis/clns"
	"github.com/choppsv1/goisis/goisis/update"
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
var GlbDebug DbgFlags

// GlbCDB is the global circuit DB for this instance
var GlbCDB = NewCircuitDB()

// GlbUpdateDB are the LSP Update DB for each level.
var GlbUpdateDB [2]*update.DB

// GlbQuit is a channel to signal go routines should end
var GlbQuit = make(chan bool)

func main() {
	var err error

	// XXX need to check for debug flags
	// areaIDPtr := flag.String("areaid", "00", "area id of this instance")
	iflistPtr := flag.String("iflist", "", "Space separated list of interfaces to run on")
	playPtr := flag.Bool("play", false, "run the playground")
	sysIDPtr := flag.String("sysid", "0000.0000.0001", "system id of this instance")
	flag.Parse()

	if *playPtr {
		playground()
		return
	}

	//
	// Initialize Debug
	//
	GlbDebug = DbgFPkt | DbgFAdj | DbgFDIS

	//
	// Initialize System and AreaIDs
	//

	GlbSystemID, err = clns.ISOEncode(*sysIDPtr)

	// XXX eventually support custom areas
	GlbAreaID = make([]byte, 1)
	GlbAreaID[0] = 0x00

	//
	// Initialize Update DB
	//
	dbdebug := func(format string, a ...interface{}) {
		debug(DbgFUpd, format, a)
	}
	if !debugIsSet(DbgFUpd) {
		dbdebug = nil
	}
	for i := clns.LIndex(0); i < 2; i++ {
		GlbUpdateDB[i] = update.NewDB(i, GlbCDB.SetAllSRM, dbdebug)
	}
	quit := make(chan bool)

	//
	// Initialize Interfaces
	//
	fmt.Printf("%v: %q\n", iflistPtr, *iflistPtr)
	for _, ifname := range strings.Fields(*iflistPtr) {
		fmt.Printf("Adding LAN link: %q\n", ifname)
		var lanlink *CircuitLAN
		lanlink, err = GlbCDB.NewCircuit(ifname, 1)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating link: %s", err)
			os.Exit(1)
		}
		GlbCDB.links[ifname] = lanlink
	}

	processPDUs(GlbCDB)

	close(quit)
}
