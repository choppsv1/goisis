// -*- coding: us-ascii-unix -*-
package main

import (
	"bytes"
	"fmt"
	"github.com/choppsv1/goisis/clns"
	"github.com/choppsv1/goisis/ether"
	"github.com/choppsv1/goisis/goisis/update"
	"github.com/choppsv1/goisis/tlv"
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
	ClearFlag(update.SxxFlag, *clns.LSPID) // No-lock uses channels
	DISInfoChanged()
	IsP2P() bool
	ProcessSNP(*RecvPDU) error
	SetFlag(update.SxxFlag, *clns.LSPID) // No-lock uses channels
	UpdateAdj(*RecvPDU) error
	UpdateAdjState(*Adj, map[tlv.Type][]tlv.Data) error
}

// =====
// Types
// =====

type DISEvent uint8

const (
	DISEventTimer DISEvent = iota // DIS Timer has expired.
	DISEventInfo                  // DIS Info has changed.
)

// SendLSP is the value passed on the sendLSP channel
type SendLSP struct {
	li    clns.LIndex
	lspid clns.LSPID
}

type ChgSxxFlag struct {
	set   bool // set or clear
	flag  update.SxxFlag
	lspid clns.LSPID
}

//
// LinkLAN is a structure holding information on a IS-IS Specific level
// operation on a LAN link.
//
type LinkLAN struct {
	circuit *CircuitLAN
	l       clns.Level
	li      clns.LIndex // level - 1 for array indexing
	updb    *update.DB

	// Hello Process
	helloInt  uint
	holdMult  uint
	priority  uint8
	lclCircID uint8
	lanID     clns.NodeID
	ourlanID  clns.NodeID
	adjdb     *AdjDB

	// Hello Process DIS
	disInfoChanged chan DISEvent
	disElected     bool

	// Update Process
	lspdb  *update.DB
	flagsC chan ChgSxxFlag
	flags  [2]update.FlagSet
}

func (e DISEvent) String() string {
	if e == DISEventTimer {
		return "DISEventTimer"
	} else {
		return "DISEventInfo"
	}
}

func (link *LinkLAN) String() string {
	return fmt.Sprintf("LANLevelLink(%s l %d)", link.circuit.CircuitBase, link.l)
}

//
// NewLinkLAN creates a LAN link for a given IS-IS level.
//
func NewLinkLAN(c *CircuitLAN, li clns.LIndex, updb *update.DB, quit <-chan bool) *LinkLAN {
	link := &LinkLAN{
		circuit:        c,
		l:              li.ToLevel(),
		li:             li,
		updb:           updb,
		priority:       clns.DefHelloPri,
		helloInt:       clns.DefHelloInt,
		holdMult:       clns.DefHelloMult,
		disInfoChanged: make(chan DISEvent),
	}
	link.adjdb = NewAdjDB(link, link.li)
	link.lspdb = c.updb[li]
	link.flags[0] = make(update.FlagSet)
	link.flags[1] = make(update.FlagSet)

	lanLinkCircuitIDs[li]++
	link.lclCircID = lanLinkCircuitIDs[li]
	copy(link.ourlanID[:], GlbSystemID)
	link.ourlanID[clns.SysIDLen] = link.lclCircID
	copy(link.lanID[:], link.ourlanID[:])

	// Record our SNPA in the map of our SNPA
	ourSNPA[ether.MACKey(c.CircuitBase.intf.HardwareAddr)] = true

	// Start Sending Hellos
	go StartLANHellos(link, link.helloInt, quit)

	// Start DIS election routine
	dur := time.Second * time.Duration(link.helloInt*2)
	time.AfterFunc(dur, func() {
		debug(DbgFDIS, "INFO: %s DIS timer expired", link)
		link.disInfoChanged <- DISEventTimer
	})

	go link.processFlags()

	return link
}

func (link *LinkLAN) IsP2P() bool {
	return false
}

// -------------------
// Adjacency Functions
// -------------------

// UpdateAdj updates an adjacency with the new PDU information.
func (link *LinkLAN) UpdateAdj(pdu *RecvPDU) error {
	link.adjdb.UpdateAdj(pdu)
	return nil
}

// DISInfoChanged is called when something has happened to require rerunning of
// DIS election on this Link.
func (link *LinkLAN) DISInfoChanged() {
	link.disInfoChanged <- DISEventInfo
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

func (link *LinkLAN) disSelfElect() {
	// Always let the update process know.
	link.updb.SetDIS(link.lclCircID, true)

	if link.disElected {
		return
	}
	link.disElected = true

	// XXX Start the CNSP timer.
}

func (link *LinkLAN) disSelfResign() {
	// Always let the update process know.
	link.updb.SetDIS(link.lclCircID, false)

	if !link.disElected {
		return
	}
	link.disElected = false

	// XXX Stop CNSP timer.
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
		link.disSelfResign()
		if electOther == nil {
			// XXX No DIS -- maybe put a zero here?
			link.lanID = link.ourlanID
		} else {
			link.lanID = newLANID
		}
	} else {
		link.disSelfElect()
	}
}

// --------
// Flooding
// --------

var SRM = update.SRM
var SSN = update.SSN

// ClearFlag clears a flag for lspid on link.
func (link *LinkLAN) ClearFlag(flag update.SxxFlag, lspid *clns.LSPID) {
	link.flagsC <- ChgSxxFlag{
		set:   false,
		flag:  flag,
		lspid: *lspid,
	}
}

// SetFlag sets a flag for lspid on link and schedules a send
func (link *LinkLAN) SetFlag(flag update.SxxFlag, lspid *clns.LSPID) {
	link.flagsC <- ChgSxxFlag{
		set:   true,
		flag:  flag,
		lspid: *lspid,
	}
}

func (link *LinkLAN) changeFlag(flag update.SxxFlag, set bool, lspid *clns.LSPID) {
	if set {
		link.flags[flag][*lspid] = struct{}{}
	} else {
		delete(link.flags[flag], *lspid)
	}
}

func (link *LinkLAN) waitFlags() {
	// XXX add a timer/ticker here to handle LSP flood pacing.
	cf := <-link.flagsC
	link.changeFlag(cf.flag, cf.set, &cf.lspid)
}

func (link *LinkLAN) gatherFlags() {
	for {
		select {
		case cf := <-link.flagsC:
			link.changeFlag(cf.flag, cf.set, &cf.lspid)
		default:
			return

		}
	}
}

// fillSNP is called to fill a SNP packet with SNPEntries
func (link *LinkLAN) fillSNP(tlvp tlv.Data) tlv.Data {
	track, err := tlv.Open(tlvp, tlv.TypeSNPEntries, nil)
	if err != nil {
		panic("No TLV space with new PDU")
	}
	for lspid := range link.flags[SSN] {
		var err error
		var p tlv.Data
		if p, err = track.Alloc(tlv.SNPEntSize); err != nil {
			// Assert that this is the error we expect.
			_ = err.(tlv.ErrNoSpace)
			break
		}
		if ok := link.lspdb.CopyLSPSNP(&lspid, p); ok {
			link.changeFlag(SSN, false, &lspid)
		} else {
			debug(DbgFFlags, "%s: LSP SSN with no LSP for %s", link, lspid)
		}
	}
	return track.Close()
}

// send all PSNP we have queued up.
func (link *LinkLAN) sendAllPSNP() {
	var pdutype clns.PDUType
	if link.li == 0 {
		pdutype = clns.PDUTypePSNPL1
	} else {
		pdutype = clns.PDUTypePSNPL2
	}

	// While we have SSN flags send PSNP
	for len(link.flags[SSN]) != 0 {
		etherp, _, psnp, tlvp := link.circuit.OpenPDU(pdutype, clns.AllLxIS[link.li])

		// Fill fixed header values
		copy(psnp[clns.HdrPSNPSrcID:], GlbSystemID)

		// Fill as many SNP entries as we can in one PDU
		endp := link.fillSNP(tlvp)

		// Send the PDU.
		link.circuit.outpkt <- link.circuit.ClosePDU(etherp, endp)
	}
}

// send all LSP we have queued up.
func (link *LinkLAN) sendAnLSP() {
	for lspid := range link.flags[SRM] {
		link.changeFlag(SRM, false, &lspid)
		etherp, payload := link.circuit.OpenFrame(clns.AllLxIS[link.li])
		if l := link.lspdb.CopyLSPPayload(&lspid, payload); l != 0 {
			link.circuit.outpkt <- CloseFrame(etherp, l)
			break
		}
		debug(DbgFFlags, "%s SRM set no LSP %s\n", link, lspid)
	}
}

// processFlags is a go routine that sets/clears flags and floods.
func (link *LinkLAN) processFlags() {
	for {
		link.waitFlags()
		for len(link.flags[SRM]) != 0 || len(link.flags[SSN]) != 0 {
			link.gatherFlags()
			link.sendAllPSNP()
			link.sendAnLSP()
		}
	}
}
