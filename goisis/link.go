// -*- coding: us-ascii-unix -*-
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

// =======
// Globals
// =======

// lanLinkCircuitIDs is used to allocate circuit IDs
var lanLinkCircuitIDs = [2]byte{0, 0}

// ==========
// Interfaces
// ==========

//
// Link represents level dependent operations on a circuit.
//
type Link interface {
	DISInfoChanged()
	ProcessPDU(*RecvPDU) error
	UpdateAdj(*RecvPDU) error
	UpdateAdjState(*Adj, map[tlv.Type][]tlv.Data) error
	ClearFlag(UpdFlag, *LSPSegment)
	ClearFlagLocked(UpdFlag, *clns.LSPID)
	SetFlag(UpdFlag, *LSPSegment)
}

// ClearSRMFlag clears an SRM flag for the given LSPSegment on the given Link
func ClearSRMFlag(l Link, lsp *LSPSegment) {
	l.ClearFlag(SRM, lsp)
}

// ClearSSNFlag clears an SRM flag for the given LSPSegment on the given Link
func ClearSSNFlag(l Link, lsp *LSPSegment) {
	l.ClearFlag(SSN, lsp)
}

// SetSRMFlag sets an SRM flag for the given LSPSegment on the given Link
func SetSRMFlag(l Link, lsp *LSPSegment) {
	l.SetFlag(SRM, lsp)
}

// SetSSNFlag sets an SRM flag for the given LSPSegment on the given Link
func SetSSNFlag(l Link, lsp *LSPSegment) {
	l.SetFlag(SSN, lsp)
}

// =====
// Types
// =====

// SendLSP is the value passed on the sendLSP channel
type SendLSP struct {
	lindex clns.LIndex
	lspid  clns.LSPID
}

//
// LinkLAN is a structure holding information on a IS-IS Specific level
// operation on a LAN link.
//
type LinkLAN struct {
	circuit   *CircuitLAN
	level     clns.Level
	lindex    clns.LIndex //  level - 1 for array indexing
	helloInt  int
	holdMult  int
	priority  uint8
	lclCircID uint8
	lanID     [clns.LANIDLen]byte
	ourlanID  [clns.LANIDLen]byte
	adjdb     *AdjDB

	flags    map[clns.LSPID]UpdFlag
	flagCond sync.Cond

	disTimer       *time.Timer
	disLock        sync.Mutex
	disInfoChanged chan bool
	disElected     bool
}

func (link *LinkLAN) String() string {
	return fmt.Sprintf("LANLevelLink(%s level %d)", link.circuit.CircuitBase, link.level)
}

//
// NewLinkLAN creates a LAN link for a given IS-IS level.
//
func NewLinkLAN(c *CircuitLAN, lindex clns.LIndex, quit chan bool) *LinkLAN {
	link := &LinkLAN{
		circuit:  c,
		level:    clns.Level(lindex + 1),
		lindex:   lindex,
		priority: clns.DefHelloPri,
		helloInt: clns.DefHelloInt,
		holdMult: clns.DefHelloMult,
		flags:    make(map[clns.LSPID]UpdFlag),
	}
	link.adjdb = NewAdjDB(link, link.lindex)

	lanLinkCircuitIDs[lindex]++
	link.lclCircID = lanLinkCircuitIDs[lindex]
	copy(link.ourlanID[:], GlbSystemID)
	link.ourlanID[clns.SysIDLen] = link.lclCircID
	copy(link.lanID[:], link.ourlanID[:])

	// Record our SNPA in the map of our SNPA
	ourSNPA[ether.MACKey(c.CircuitBase.intf.HardwareAddr)] = true

	// Start Sending Hellos
	go SendLANHellos(link, link.helloInt, quit)

	// Start DIS election routine
	go link.startElectingDIS()

	go link.sendLSPs()

	return link
}

// -------------------
// Adjacency Functions
// -------------------

// UpdateAdj updates an adjacency with the new PDU information.
func (link *LinkLAN) UpdateAdj(pdu *RecvPDU) error {
	link.adjdb.UpdateAdj(pdu)
	return nil
}

//
// ReElectDIS is a go routine that waits for events to trigger DIS reelection on
// the link. Initially this is a timer, and then it's based on changes in the
// hello process.
//
func (link *LinkLAN) startElectingDIS() {
	link.disInfoChanged = make(chan bool)
	dur := time.Second * time.Duration(link.helloInt*2)
	link.disTimer = time.AfterFunc(dur, func() {
		debug(DbgFDIS, "INFO: %s DIS timer expired", link)
		link.disLock.Lock()
		link.disTimer = nil
		link.disLock.Unlock()
		link.disInfoChanged <- true
	})
	for range link.disInfoChanged {
		debug(DbgFDIS, "INFO: %s Received disInfoChanged notification", link)
		link.disElect()
	}
}

//
// DISInfoChanged is called when something has happened to require rerunning of
// DIS election on this LAN.
//
func (link *LinkLAN) DISInfoChanged() {
	link.disLock.Lock()
	defer link.disLock.Unlock()
	if link.disTimer == nil {
		link.disInfoChanged <- true
	}
}

//
// UpdateAdjState updates the adj state according to the TLV found in the IIH
//
func (link *LinkLAN) UpdateAdjState(a *Adj, tlvs map[tlv.Type][]tlv.Data) error {
	// Walk neighbor TLVs if we see ourselves mark adjacency Up.
	for _, ntlv := range tlvs[tlv.TypeISNeighbors] {
		addrs, err := ntlv.ISNeighborsValue()
		if err != nil {
			logger.Printf("ERROR: processing IS Neighbors TLV from %s: %v", a, err)
			return err
		}
		for _, snpa := range addrs {
			if bytes.Equal(snpa, link.circuit.getOurSNPA()) {
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
func (link *LinkLAN) disFindBest() (bool, *Adj) {
	electPri := link.priority
	electID := GlbSystemID
	var elect *Adj
	count := 0
	for _, a := range link.adjdb.srcidMap {
		if a.State != AdjStateUp {
			debug(DbgFDIS, "%s skipping non-up adj %s", link, a)
			continue
		}
		count++
		if a.priority > electPri {
			debug(DbgFDIS, "%s adj %s better priority %d", link, a, a.priority)
			elect = a
			electPri = a.priority
			electID = a.sysid[:]
		} else if a.priority == electPri {
			debug(DbgFDIS, "%s adj %s same priority %d", link, a, a.priority)
			if bytes.Compare(a.sysid[:], electID) > 0 {
				elect = a
				electPri = a.priority
				electID = a.sysid[:]
			}
		} else {
			debug(DbgFDIS, "%s adj %s worse priority %d", link, a, a.priority)
		}
	}
	if count == 0 {
		debug(DbgFDIS, "%s no adj, no dis", link)
		// No adjacencies, no DIS
		return false, nil
	}
	return elect == nil, elect
}

func (link *LinkLAN) disElect() {
	debug(DbgFDIS, "Running DIS election on %s", link)

	link.adjdb.lock.Lock()
	defer link.adjdb.lock.Unlock()

	var newLANID clns.NodeID
	oldLANID := link.lanID

	electUs, electOther := link.disFindBest()
	if electUs {
		debug(DbgFDIS, "%s electUS", link)
		newLANID = link.ourlanID
	} else if electOther != nil {
		debug(DbgFDIS, "%s electOther %s", link, electOther)
		newLANID = electOther.lanID
	}

	if oldLANID == newLANID {
		debug(DbgFDIS, "Same DIS elected: %s", newLANID)
		return
	}

	debug(DbgFDIS, "DIS change: old %s new %s", oldLANID, newLANID)

	if !electUs {
		if link.disElected {
			link.disElected = false
			// XXX perform DIS resign duties
		}
		if electOther == nil {
			// XXX No DIS
			link.lanID = link.ourlanID
		} else {
			link.lanID = newLANID
		}
	} else if !link.disElected {
		link.disElected = true
		// XXX start new DIS duties
	}
	// XXX Update Process: signal DIS change
}

// --------
// Flooding
// --------

// ClearFlag clears a flag for LSPSegment on link.
func (link *LinkLAN) ClearFlag(flag UpdFlag, lsp *LSPSegment) {
	link.flagCond.L.Lock()
	link.ClearFlagLocked(flag, &lsp.lspid)
	link.flagCond.L.Unlock()
}

// ClearFlagLocked clears a flag for LSPSegment on link without locking
func (link *LinkLAN) ClearFlagLocked(flag UpdFlag, lspid *clns.LSPID) {
	nflag := link.flags[*lspid] & ^flag
	if nflag != 0 {
		link.flags[*lspid] = nflag
	} else {
		delete(link.flags, *lspid)
	}
	if (GlbDebug & DbgFFlags) != 0 {
		debug(DbgFFlags, "Clear %s on %s for %s", flag, link, lspid)
	}
}

// SetFlag sets a flag for LSPSegment on link and schedules a send
func (link *LinkLAN) SetFlag(flag UpdFlag, lsp *LSPSegment) {
	link.flagCond.L.Lock()
	defer link.flagCond.L.Unlock()
	link.flags[lsp.lspid] |= flag
	if (GlbDebug & DbgFFlags) != 0 {
		debug(DbgFFlags, "Set %s on %s for %s", flag, link, lsp)
	}
	link.flagCond.Signal()
}

// XXX this go rtn has now quit
func (link *LinkLAN) sendLSPs() {
	link.flagCond.L.Lock()
	for {
		for len(link.flags) == 0 {
			debug(DbgFFlags, "Waiting for LSP flags on %s", link)
			link.flagCond.Wait()
		}
		// locked, send LSPs
		for lspid, flags := range link.flags {
			debug(DbgFFlags, "Clearing flags %s for %s on %s",
				flags, lspid, link)
			link.ClearFlagLocked(flags, &lspid)
		}
	}
}
