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

// GlbISType specifies which levels IS-IS is enabled on
var GlbISType clns.LevelFlag

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

// Slicer grabs a slice from a byte slice given a start and length.
func Slicer(b []byte, start int, length int) []byte {
	return b[start : start+length]
}

func main() {
	var err error

	// XXX need to check for debug flags
	// areaIDPtr := flag.String("areaid", "00", "area id of this instance")
	iflistPtr := flag.String("iflist", "", "Space separated list of interfaces to run on")
	playPtr := flag.Bool("play", false, "run the playground")
	isTypePtr := flag.String("istype", "level-1", "level-1, level-1-2, level-2-only")
	sysIDPtr := flag.String("sysid", "0000.0000.0001", "system id of this instance")
	flag.Parse()

	if *playPtr {
		playground()
		return
	}

	//
	// Initialize Debug
	//
	GlbDebug = DbgFPkt | DbgFAdj | DbgFDIS | DbgFUpd

	//
	// Initialize System and AreaIDs
	//

	GlbSystemID, err = clns.ISOEncode(*sysIDPtr)
	if err != nil {
		panic(err)
	}
	fmt.Printf("System ID: %s\n", GlbSystemID)

	// XXX eventually support custom areas
	GlbAreaID = make([]byte, 1)
	GlbAreaID[0] = 0x00

	switch *isTypePtr {
	case "level-1":
		GlbISType = clns.L1Flag
		break
	case "level-2-only":
		GlbISType = clns.L2Flag
		break
	case "level-1-2":
		GlbISType = clns.L1Flag | clns.L2Flag
		break
	default:
		panic(fmt.Sprintf("Invalid istype %s", *isTypePtr))
	}
	fmt.Printf("IS-IS %s router\n", GlbISType)

	//
	// Initialize Update DB
	//
	dbdebug := func(format string, a ...interface{}) {
		debug(DbgFUpd, format, a)
	}
	if !debugIsSet(DbgFUpd) {
		dbdebug = func(format string, a ...interface{}) {}
	}
	for i := clns.LIndex(0); i < 2; i++ {
		if GlbISType.IsLevelEnabled(i.ToLevel()) {
			GlbUpdateDB[i] = update.NewDB(i, GlbCDB.SetAllSRM, dbdebug)
		}
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
			fmt.Fprintf(os.Stderr, "Error creating link: %s\n", err)
			os.Exit(1)
		}
		GlbCDB.links[ifname] = lanlink
	}
	for _, db := range GlbUpdateDB {
		if db != nil {
			go db.Run()
		}
	}

	processPDUs(GlbCDB)

	close(quit)
}
