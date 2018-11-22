package main

import (
	"flag"
	"fmt"
	"github.com/choppsv1/goisis/clns"
	"github.com/choppsv1/goisis/goisis/update"
	"net"
	"strings"
)

//
// Consolidate these into instance type to support multi-instance.
//

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

// GlbUpdateDB are the LSP Update DB for each level.
var GlbUpdateDB [2]*update.DB

// GlbQuit is a channel to signal go routines should end
var GlbQuit = make(chan bool)

func main() {
	var err error

	// XXX need to check for debug flags
	iflistPtr := flag.String("iflist", "", "Space separated list of interfaces to run on")
	playPtr := flag.Bool("play", false, "run the playground")
	isTypePtr := flag.String("istype", "level-1", "level-1, level-1-2, level-2-only")
	sysIDPtr := flag.String("sysid", "0000.0000.0001", "system id of this instance")
	areaIDPtr := flag.String("area", "00", "area of this instance")
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
	// Initialize instance type
	//
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
	// Initialize System and AreaIDs
	//
	if GlbSystemID, err = clns.ISOEncode(*sysIDPtr); err != nil {
		panic(err)
	}
	if GlbAreaID, err = clns.ISOEncode(*areaIDPtr); err != nil {
		panic(err)
	}
	if GlbISType.IsLevelEnabled(1) {
		fmt.Printf("System ID: %s Area ID: %s\n", GlbSystemID, GlbAreaID)
	} else {
		fmt.Printf("System ID: %s\n", GlbSystemID)
	}

	//
	// Initialize Circuit DB
	//
	cdb := NewCircuitDB()

	//
	// Initialize Update Process
	//
	var updb [2]*update.DB
	dbdebug := func(format string, a ...interface{}) {}
	if debugIsSet(DbgFUpd) {
		dbdebug = func(format string, a ...interface{}) {
			debug(DbgFUpd, format, a)
		}
	}
	for l := clns.Level(1); l <= 2; l++ {
		if GlbISType.IsLevelEnabled(l) {
			updb[l] = update.NewDB(l, cdb.SetAllSRM, dbdebug)
		}
	}

	//
	// Initialize Interfaces
	//
	fmt.Printf("%v: %q\n", iflistPtr, *iflistPtr)
	for _, ifname := range strings.Fields(*iflistPtr) {
		fmt.Printf("Adding LAN link: %q\n", ifname)
		var lanlink *CircuitLAN
		lanlink, err = cdb.NewCircuit(ifname, updb, 1)
		if err != nil {
			panic(fmt.Sprintf("Error creating link: %s\n", err))
		}
		cdb.links[ifname] = lanlink
	}
	for _, db := range GlbUpdateDB {
		if db != nil {
			go db.Run()
		}
	}

	processPDUs(cdb)

	close(GlbQuit)
}
