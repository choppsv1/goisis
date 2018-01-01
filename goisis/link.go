// -*- coding: us-ascii-unix -*-
package main

import (
	"bytes"
	"fmt"
	"github.com/choppsv1/goisis/clns"
	"github.com/choppsv1/goisis/ether"
	"github.com/choppsv1/goisis/goisis/update"
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
	ProcessLSP(*RecvPDU) error
	ProcessSNP(*RecvPDU) error
	UpdateAdj(*RecvPDU) error
	UpdateAdjState(*Adj, map[tlv.Type][]tlv.Data) error
	ClearFlag(FlagIndex, *clns.LSPID)
	ClearFlagLocked(FlagIndex, *clns.LSPID)
	SetFlag(FlagIndex, *clns.LSPID)
}

// ClearSRMFlag clears an SRM flag for the given LSPID on the given Link
func ClearSRMFlag(l Link, lspid *clns.LSPID) {
	l.ClearFlag(SRM, lspid)
}

// ClearSSNFlag clears an SRM flag for the given LSPID on the given Link
func ClearSSNFlag(l Link, lspid *clns.LSPID) {
	l.ClearFlag(SSN, lspid)
}

// SetSRMFlag sets an SRM flag for the given LSPID on the given Link
func SetSRMFlag(l Link, lspid *clns.LSPID) {
	l.SetFlag(SRM, lspid)
}

// SetSSNFlag sets an SRM flag for the given LSPID on the given Link
func SetSSNFlag(l Link, lspid *clns.LSPID) {
	l.SetFlag(SSN, lspid)
}

// =====
// Types
// =====

// FlagIndex Update process flooding flags (not true flags)
type FlagIndex int

// Update process flooding flags
const (
	SRM FlagIndex = iota
	SSN
)

var flagStrings = [2]string{
	"SRM",
	"SSN",
}

func (flag FlagIndex) String() string {
	return flagStrings[flag]
}

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
	circuit *CircuitLAN
	level   clns.Level
	lindex  clns.LIndex //  level - 1 for array indexing

	// Hello Process
	helloInt  int
	holdMult  int
	priority  uint8
	lclCircID uint8
	lanID     [clns.LANIDLen]byte
	ourlanID  [clns.LANIDLen]byte
	adjdb     *AdjDB

	// Hello Process DIS
	disTimer       *time.Timer
	disLock        sync.Mutex
	disInfoChanged chan bool
	disElected     bool

	// Update Process
	lspdb    *update.DB
	flags    [2]map[clns.LSPID]bool
	flagCond sync.Cond
}

func (link *LinkLAN) String() string {
	return fmt.Sprintf("LANLevelLink(%s level %d)", link.circuit.CircuitBase, link.level)
}

//
// NewLinkLAN creates a LAN link for a given IS-IS level.
//
func NewLinkLAN(c *CircuitLAN, lindex clns.LIndex, quit <-chan bool) *LinkLAN {
	link := &LinkLAN{
		circuit:  c,
		level:    clns.Level(lindex + 1),
		lindex:   lindex,
		priority: clns.DefHelloPri,
		helloInt: clns.DefHelloInt,
		holdMult: clns.DefHelloMult,
		flags: [2]map[clns.LSPID]bool{
			make(map[clns.LSPID]bool),
			make(map[clns.LSPID]bool)},
	}
	link.adjdb = NewAdjDB(link, link.lindex)
	link.lspdb = GlbUpdateDB[lindex]

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

	go link.processFlags()

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

// ClearFlag clears a flag for lspid on link.
func (link *LinkLAN) ClearFlag(flag FlagIndex, lspid *clns.LSPID) {
	link.flagCond.L.Lock()
	link.ClearFlagLocked(flag, lspid)
	link.flagCond.L.Unlock()
}

// ClearFlagLocked clears a flag for lspid on link without locking
func (link *LinkLAN) ClearFlagLocked(flag FlagIndex, lspid *clns.LSPID) {
	delete(link.flags[flag], *lspid)
	if (GlbDebug & DbgFFlags) != 0 {
		debug(DbgFFlags, "Clear %s on %s for %s", flag, link, lspid)
	}
}

// SetFlag sets a flag for lspid on link and schedules a send
func (link *LinkLAN) SetFlag(flag FlagIndex, lspid *clns.LSPID) {
	link.flagCond.L.Lock()
	defer link.flagCond.L.Unlock()
	link.flags[flag][*lspid] = true
	if (GlbDebug & DbgFFlags) != 0 {
		debug(DbgFFlags, "Set %s on %s for %s", flag, link, lspid)
	}
	link.flagCond.Signal()
}

// _processFlags is the guts of the sendLSP function
func (link *LinkLAN) _processFlags() {
	link.flagCond.L.Lock()
	llen := len(link.flags[SRM])
	plen := len(link.flags[SSN])
	for llen+plen == 0 {
		debug(DbgFFlags, "Waiting for LSP flags on %s", link)
		link.flagCond.Wait()
	}

	// ---------------------------------
	// Locked - Process 1 LSP and 1 PSNP
	// ---------------------------------

	//
	// Get an LSP PDU
	//
	var lspf ether.Frame
	// Only process one LSP per lock
	for lspid := range link.flags[SRM] {
		var l int
		etherp, payload := link.circuit.OpenFrame(clns.AllLxIS[link.lindex])
		if l = link.lspdb.CopyLSPPayload(&lspid, payload); l == 0 {
			break
		}
		// Clear the flag when the send is eminent, doesn't have to
		// happen now though.
		link.ClearFlagLocked(SRM, &lspid)
		CloseFrame(etherp, l)
		lspf = etherp
		break
	}

	//
	// Get a PSNP PDU
	//
	var psnpf ether.Frame
	if plen != 0 {
		psnpf = link.getPSNPLocked()
	}

	link.flagCond.L.Unlock()

	//
	// Unlocked
	//

	// Send LSP
	if lspf != nil {
		link.circuit.outpkt <- lspf
	}

	// Send PSNP
	if psnpf != nil {
		link.circuit.outpkt <- psnpf
	}
}

// XXX this go rtn has no quit
func (link *LinkLAN) processFlags() {
	for {
		link._processFlags()
	}
}

// fillSNPLocked is called to fill a SNP packet with SNPEntries the flagCond
// Lock has is held.
func (link *LinkLAN) fillSNPLocked(tlvp tlv.Data) tlv.Data {
	track, _ := tlv.Open(tlvp, tlv.TypeSNPEntries, nil)
	for lspid := range link.flags[SSN] {
		var err error
		var p tlv.Data
		if p, err = track.Alloc(tlv.SNPEntSize); err != nil {
			// Assert that this is the error we expect.
			_ = err.(tlv.ErrNoSpace)
			break
		}
		// XXX maybe it's a bug if this fails?
		if ok := link.lspdb.CopyLSPSNP(&lspid, p); ok {
			link.ClearFlagLocked(SSN, &lspid)
		} else {
			logger.Panicf("Got LSP SSN with no LSP for %s", lspid)
		}
	}
	return track.Close()
}

// getPSNPLocked is called to get one PSNP PDU worth of SNP based on SSN flags,
// the flagCond Lock is held.
func (link *LinkLAN) getPSNPLocked() ether.Frame {
	var pdutype clns.PDUType
	if link.lindex == 0 {
		pdutype = clns.PDUTypePSNPL1
	} else {
		pdutype = clns.PDUTypePSNPL2
	}
	etherp, _, psnp, tlvp := link.circuit.OpenPDU(pdutype, clns.AllLxIS[link.lindex])

	// Fill fixed header values
	copy(psnp[clns.HdrPSNPSrcID:], GlbSystemID)

	// Fill as many SNP entries as we can in one PDU
	endp := link.fillSNPLocked(tlvp)

	link.circuit.ClosePDU(etherp, endp)

	return etherp
}
