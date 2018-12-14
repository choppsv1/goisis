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

// GlbSystemID is the system ID of this IS-IS instance
var GlbHostname string

// GlbAreaIDs is the slice of our area IDs
var GlbAreaIDs [][]byte

// GlbNLPID holds an array of the NLPID that we support
// var GlbNLPID = []byte{clns.NLPIDIPv4}
var GlbNLPID = []byte{clns.NLPIDIPv4, clns.NLPIDIPv6}

// GlbDebug are the enabled debugs.
var GlbDebug DbgFlags

// GlbTrace are the enabled traces.
var GlbTrace DbgFlags

// GlbQuit is a channel to signal go routines should end
var GlbQuit = make(chan bool)

func splitArg(argp *string) []string {
	if argp == nil {
		return nil
	}
	return strings.FieldsFunc(*argp, func(r rune) bool {
		return r == ' ' || r == '\t' || r == ','
	})
}

func main() {
	var err error

	// XXX need to check for debug flags
	iflistPtr := flag.String("iflist", "", "Space separated list of interfaces to run on")
	playPtr := flag.Bool("play", false, "run the playground")
	areaIDPtr := flag.String("area", "00", "area of this instance")
	dbgIDPtr := flag.String("debug", "",
		"strsep list of debug flags: all or adj,dis,flags,packet,update")
	isTypePtr := flag.String("istype", "l-1", "l-1, l-1-2, l-2-only")
	sysIDPtr := flag.String("sysid", "0000.0000.0001", "system id of this instance")
	traceIDPtr := flag.String("trace", "",
		"strsep list of debug flags: all or adj,dis,flags,packet,update")
	flag.Parse()

	if *playPtr {
		playground()
		return
	}

	// Initialize trace flags.
	if strings.Compare(*traceIDPtr, "all") == 0 {
		for fstr := range FlagNames {
			GlbTrace |= FlagNames[fstr]
		}
	} else {
		for _, s := range splitArg(traceIDPtr) {
			flag, ok := FlagNames[s]
			if !ok {
				fmt.Printf("Unknown trace flag: %s\n", s)
				continue
			}
			GlbTrace |= flag
		}
	}

	// Initialize debug flags.
	if strings.Compare(*dbgIDPtr, "all") == 0 {
		for s := range FlagNames {
			GlbDebug |= FlagNames[s]
		}
	} else {
		for _, s := range splitArg(dbgIDPtr) {
			flag, ok := FlagNames[s]
			if !ok {
				fmt.Printf("Unknown debug flag: %s\n", s)
				continue
			}
			GlbDebug |= flag
		}
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
	for _, s := range splitArg(areaIDPtr) {
		a, err := clns.ISOEncode(s)
		if err != nil {
			panic(err)
		}
		GlbAreaIDs = append(GlbAreaIDs, a)
		if len(GlbAreaIDs) > clns.MaxArea {
			panic("More areas than allowed")
		}
	}

	if GlbHostname, err := os.Hostname(); err != nil {
		info("WARNING: Error getting hostname: %s", err)
		GlbHostname = nil
	}

	if GlbISType.IsLevelEnabled(1) {
		fmt.Printf("System ID: %s Area IDs: %v\n", GlbSystemID, GlbAreaIDs)
	} else {
		fmt.Printf("System ID: %s\n", GlbSystemID)
	}

	// Initialize Update Process

	var updb [2]*update.DB
	dbdebug := func(format string, a ...interface{}) {}
	if debugIsSet(DbgFUpd) {
		dbdebug = func(format string, a ...interface{}) {
			debug(DbgFUpd, format, a...)
		}
	}
	for l := clns.Level(1); l <= 2; l++ {
		if GlbISType.IsLevelEnabled(l) {
			li := l.ToIndex()
			updb[li] = update.NewDB(GlbSystemID[:], l, dbdebug)
		}
	}

	// Initialize Circuit DB

	cdb := NewCircuitDB()

	// Add interfaces
	fmt.Printf("%v: %q\n", iflistPtr, *iflistPtr)
	for _, ifname := range splitArg(iflistPtr) {
		fmt.Printf("Adding LAN link: %q\n", ifname)
		_, err = cdb.NewCircuit(ifname, GlbISType, updb)
		if err != nil {
			panicf("Error creating circuit: %s\n", err)
		}
	}

	ticker := time.NewTicker(time.Second * 120)
	for _ = range ticker.C {
		info("Keep Alive\n")
	}

	close(GlbQuit)
}
