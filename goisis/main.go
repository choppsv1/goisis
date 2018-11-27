package main

import (
	"flag"
	"fmt"
	"github.com/choppsv1/goisis/clns"
	"github.com/choppsv1/goisis/goisis/update"
	"strings"
	"time"
)

//
// Consolidate these into instance type to support multi-instance.
//

// GlbISType specifies which levels IS-IS is enabled on
var GlbISType clns.LevelFlag

// GlbSystemID is the system ID of this IS-IS instance
var GlbSystemID []byte

// GlbAreaID is the area this IS-IS instance is in.
var GlbAreaID []byte

// GlbNLPID holds an array of the NLPID that we support
// var GlbNLPID = []byte{clns.NLPIDIPv4}
var GlbNLPID = []byte{clns.NLPIDIPv4, clns.NLPIDIPv6}

// GlbDebug are the enable debug.
var GlbDebug DbgFlags

// GlbQuit is a channel to signal go routines should end
var GlbQuit = make(chan bool)

func main() {
	var err error

	// XXX need to check for debug flags
	iflistPtr := flag.String("iflist", "", "Space separated list of interfaces to run on")
	playPtr := flag.Bool("play", false, "run the playground")
	areaIDPtr := flag.String("area", "00", "area of this instance")
	dbgIDPtr := flag.String("debug", "",
		"strsep list of debug flags: adj,dis,flags,packet,update")
	isTypePtr := flag.String("istype", "l-1", "l-1, l-1-2, l-2-only")
	sysIDPtr := flag.String("sysid", "0000.0000.0001", "system id of this instance")
	flag.Parse()

	if *playPtr {
		playground()
		return
	}

	// Initialize debug flags.
	for _, fstr := range strings.Split(*dbgIDPtr, ",") {
		flag, ok := FlagNames[fstr]
		if !ok {
			fmt.Printf("Unknown debug flag: %s\n", fstr)
			continue
		}
		GlbDebug |= flag
	}

	// Initialize instance type
	switch *isTypePtr {
	case "l-1":
		GlbISType = clns.L1Flag
		break
	case "l-2-only":
		GlbISType = clns.L2Flag
		break
	case "l-1-2":
		GlbISType = clns.L1Flag | clns.L2Flag
		break
	default:
		panic(fmt.Sprintf("Invalid istype %s", *isTypePtr))
	}
	fmt.Printf("IS-IS %s router\n", GlbISType)

	// Initialize System and AreaIDs

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

	// Initialize Circuit DB

	cdb := NewCircuitDB()

	// Initialize Update Process

	var updb [2]*update.DB
	dbdebug := func(format string, a ...interface{}) {}
	if debugIsSet(DbgFUpd) {
		dbdebug = func(format string, a ...interface{}) {
			debug(DbgFUpd, format, a)
		}
	}
	for l := clns.Level(1); l <= 2; l++ {
		if GlbISType.IsLevelEnabled(l) {
			li := l.ToIndex()
			updb[li] = update.NewDB(GlbSystemID[:], l, cdb.flagsC, dbdebug)
		}
	}

	// Add interfaces

	fmt.Printf("%v: %q\n", iflistPtr, *iflistPtr)
	for _, ifname := range strings.Fields(*iflistPtr) {
		fmt.Printf("Adding LAN link: %q\n", ifname)
		_, err = cdb.NewCircuit(ifname, GlbISType, updb)
		if err != nil {
			panic(fmt.Sprintf("Error creating link: %s\n", err))
		}
	}

	ticker := time.NewTicker(time.Second * 10)
	for _ = range ticker.C {
		fmt.Printf("Keep Alive\n")
	}

	close(GlbQuit)
}
