package main

import (
	"bytes"
	"fmt"
	"github.com/choppsv1/goisis/clns"
	"github.com/choppsv1/goisis/ether"
	"github.com/choppsv1/goisis/tlv"
	"sync"
	"time"
)

// lanLinkCircuitIDs is used to allocate circuit IDs
var lanLinkCircuitIDs = [2]byte{0, 0}

//
// LANLink is a structure holding information on a IS-IS Specific level
// operation on a LAN link.
//
type LANLink struct {
	link      *CircuitLAN
	level     clns.Level
	lindex    clns.LIndex //  level - 1 for array indexing
	helloInt  int
	holdMult  int
	priority  uint8
	lclCircID uint8
	lanID     [clns.LANIDLen]byte
	ourlanID  [clns.LANIDLen]byte
	adjdb     *AdjDB

	disTimer       *time.Timer
	disLock        sync.Mutex
	disInfoChanged chan bool
	disElected     bool
}

func (llink *LANLink) String() string {
	return fmt.Sprintf("LANLevelLink(%s level %d)", llink.link.LinkCommon, llink.level)
}

//
// NewLANLink creates a LAN link for a given IS-IS level.
//
func NewLANLink(link *CircuitLAN, lindex clns.LIndex, quit chan bool) *LANLink {
	llink := &LANLink{
		link:     link,
		level:    clns.Level(lindex + 1),
		lindex:   lindex,
		priority: clns.DefHelloPri,
		helloInt: clns.DefHelloInt,
		holdMult: clns.DefHelloMult,
	}

	llink.adjdb = NewAdjDB(llink, llink.lindex)

	lanLinkCircuitIDs[lindex]++
	llink.lclCircID = lanLinkCircuitIDs[lindex]
	copy(llink.ourlanID[:], GlbSystemID)
	llink.ourlanID[clns.SysIDLen] = llink.lclCircID
	copy(llink.lanID[:], llink.ourlanID[:])

	// Record our SNPA in the map of our SNPA
	ourSNPA[ether.MACKey(link.LinkCommon.intf.HardwareAddr)] = true

	// Start Sending Hellos
	go SendLANHellos(llink, llink.helloInt, quit)

	// Start DIS election routine
	go llink.startElectingDIS()

	return llink
}

// ProcessPDU is called with a frame received on this link. Currently all
// received packets are handled serially in the order they arrive (using a
// single go routine). This could be changed in the future don't rely on it.
func (llink *LANLink) ProcessPDU(pdu *RecvPDU) error {
	// Validate ethernet values.
	// var src, dst [clns.SNPALen]byte
	level, err := pdu.pdutype.GetPDULevel()
	if err != nil {
		return err
	}

	switch pdu.pdutype {
	case clns.PDUTypeIIHLANL1:
		return RecvLANHello(llink, pdu, level-1)
	case clns.PDUTypeIIHLANL2:
		return RecvLANHello(llink, pdu, level-1)
	case clns.PDUTypeLSPL1:
		debug(DbgFPkt, "INFO: ignoring LSPL1 on %s for now", llink)
	case clns.PDUTypeLSPL2:
		debug(DbgFPkt, "INFO: ignoring LSPL2 on %s for now", llink)
	case clns.PDUTypeCSNPL1:
		debug(DbgFPkt, "INFO: ignoring CSNPL1 on %s for now", llink)
	case clns.PDUTypeCSNPL2:
		debug(DbgFPkt, "INFO: ignoring CSNPL2 on %s for now", llink)
	case clns.PDUTypePSNPL1:
		debug(DbgFPkt, "INFO: ignoring PSNPL1 on %s for now", llink)
	case clns.PDUTypePSNPL2:
		debug(DbgFPkt, "INFO: ignoring PSNPL2 on %s for now", llink)
	}
	return nil
}

// ===================
// Adjacency Functions
// ===================

// UpdateAdj updates an adjacency with the new PDU information.
func (llink *LANLink) UpdateAdj(pdu *RecvPDU) error {
	llink.adjdb.UpdateAdj(pdu)
	return nil
}

//
// ReElectDIS is a go routine that waits for events to trigger DIS reelection on
// the llink. Initially this is a timer, and then it's based on changes in the
// hello process.
//
func (llink *LANLink) startElectingDIS() {
	llink.disInfoChanged = make(chan bool)
	dur := time.Second * time.Duration(llink.helloInt*2)
	llink.disTimer = time.AfterFunc(dur, func() {
		debug(DbgFDIS, "INFO: %s DIS timer expired", llink)
		llink.disLock.Lock()
		llink.disTimer = nil
		llink.disLock.Unlock()
		llink.disInfoChanged <- true
	})
	for range llink.disInfoChanged {
		debug(DbgFDIS, "INFO: %s Received disInfoChanged notification", llink)
		llink.disElect()
	}
}

//
// DISInfoChanged is called when something has happened to require rerunning of
// DIS election on this LAN.
//
func (llink *LANLink) DISInfoChanged() {
	llink.disLock.Lock()
	defer llink.disLock.Unlock()
	if llink.disTimer == nil {
		llink.disInfoChanged <- true
	}
}

//
// UpdateAdjState updates the adj state according to the TLV found in the IIH
//
func (llink *LANLink) UpdateAdjState(a *Adj, tlvs map[tlv.Type][]tlv.Data) error {
	// Walk neighbor TLVs if we see ourselves mark adjacency Up.
	for _, ntlv := range tlvs[tlv.TypeISNeighbors] {
		addrs, err := ntlv.ISNeighborsValue()
		if err != nil {
			logger.Printf("ERROR: processing IS Neighbors TLV from %s: %v", a, err)
			return err
		}
		for _, snpa := range addrs {
			if bytes.Equal(snpa, llink.link.getOurSNPA()) {
				a.State = AdjStateUp
				break
			}
		}
		if a.State == AdjStateUp {
			break
		}
	}
	return nil
}

// ------------
// DIS election
// ------------

//
// disFindBest - ISO10589: 8.4.5
//
// Locking: called with adjdb locked
//
func (llink *LANLink) disFindBest() (bool, *Adj) {
	electPri := llink.priority
	electID := GlbSystemID
	var elect *Adj
	count := 0
	for _, a := range llink.adjdb.srcidMap {
		if a.State != AdjStateUp {
			debug(DbgFDIS, "%s skipping non-up adj %s", llink, a)
			continue
		}
		count++
		if a.priority > electPri {
			debug(DbgFDIS, "%s adj %s better priority %d", llink, a, a.priority)
			elect = a
			electPri = a.priority
			electID = a.sysid[:]
		} else if a.priority == electPri {
			debug(DbgFDIS, "%s adj %s same priority %d", llink, a, a.priority)
			if bytes.Compare(a.sysid[:], electID) > 0 {
				elect = a
				electPri = a.priority
				electID = a.sysid[:]
			}
		} else {
			debug(DbgFDIS, "%s adj %s worse priority %d", llink, a, a.priority)
		}
	}
	if count == 0 {
		debug(DbgFDIS, "%s no adj, no dis", llink)
		// No adjacencies, no DIS
		return false, nil
	}
	return elect == nil, elect
}

func (llink *LANLink) disElect() {
	debug(DbgFDIS, "Running DIS election on %s", llink)

	llink.adjdb.lock.Lock()
	defer llink.adjdb.lock.Unlock()

	var newLANID clns.NodeID
	oldLANID := llink.lanID

	electUs, electOther := llink.disFindBest()
	if electUs {
		debug(DbgFDIS, "%s electUS", llink)
		newLANID = llink.ourlanID
	} else if electOther != nil {
		debug(DbgFDIS, "%s electOther %s", llink, electOther)
		newLANID = electOther.lanID
	}

	if oldLANID == newLANID {
		debug(DbgFDIS, "Same DIS elected: %s", newLANID)
		return
	}

	debug(DbgFDIS, "DIS change: old %s new %s", oldLANID, newLANID)

	if !electUs {
		if llink.disElected {
			llink.disElected = false
			// XXX perform DIS resign duties
		}
		if electOther == nil {
			// XXX No DIS
			llink.lanID = llink.ourlanID
		} else {
			llink.lanID = newLANID
		}
	} else if !llink.disElected {
		llink.disElected = true
		// XXX start new DIS duties
	}
	// XXX Update Process: signal DIS change
}
