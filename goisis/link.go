// -*- coding: us-ascii-unix -*-
package main

import (
	"fmt"
	"github.com/choppsv1/goisis/clns"
	"github.com/choppsv1/goisis/ether"
	"github.com/choppsv1/goisis/goisis/update"
	"github.com/choppsv1/goisis/tlv"
	"net"
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
	IsP2P() bool
	SetFlag(update.SxxFlag, *clns.LSPID) // No-lock uses channels
	RecvHello(*RecvPDU) bool
	GetOurSNPA() net.HardwareAddr
	ExpireAdj(clns.SystemID)
}

// =====
// Types
// =====

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

	// Hello Process
	expireC    chan clns.SystemID
	iihpkt     chan *RecvPDU
	disTimer   *time.Timer
	disElected bool
	snpaMap    map[clns.SNPA]*Adj
	srcidMap   map[clns.SystemID]*Adj

	// Update Process
	lspdb  *update.DB
	flagsC chan ChgSxxFlag
	flags  [2]update.FlagSet
}

func (link *LinkLAN) String() string {
	return fmt.Sprintf("LANLevelLink(%s l %d)", link.circuit.CircuitBase, link.l)
}

//
// NewLinkLAN creates a LAN link for a given IS-IS level.
//
func NewLinkLAN(c *CircuitLAN, li clns.LIndex, updb *update.DB, quit <-chan bool) *LinkLAN {
	link := &LinkLAN{
		circuit:  c,
		l:        li.ToLevel(),
		li:       li,
		updb:     updb,
		priority: 0, // clns.DefHelloPri,
		helloInt: clns.DefHelloInt,
		holdMult: clns.DefHelloMult,
		expireC:  make(chan clns.SystemID, 10),
		iihpkt:   make(chan *RecvPDU, 3),
		snpaMap:  make(map[clns.SNPA]*Adj),
		srcidMap: make(map[clns.SystemID]*Adj),
		flagsC:   make(chan ChgSxxFlag, 10),
		flags:    [2]update.FlagSet{make(update.FlagSet), make(update.FlagSet)},
		lspdb:    c.updb[li],
	}
	lanLinkCircuitIDs[li]++
	link.lclCircID = lanLinkCircuitIDs[li]
	copy(link.ourlanID[:], GlbSystemID)
	link.ourlanID[clns.SysIDLen] = link.lclCircID
	copy(link.lanID[:], link.ourlanID[:])

	// Record our SNPA in the map of our SNPA
	ourSNPA[ether.MACKey(c.CircuitBase.intf.HardwareAddr)] = true

	// Start Sending Hellos
	StartHelloProcess(link, link.helloInt, quit)

	// Start DIS election routine
	dur := time.Second * time.Duration(link.helloInt*2)
	link.disTimer = time.NewTimer(dur)

	go link.processFlags()

	return link
}

func (link *LinkLAN) IsP2P() bool {
	return false
}

func (link *LinkLAN) GetOurSNPA() net.HardwareAddr {
	return link.circuit.CircuitBase.intf.HardwareAddr
}

func (link *LinkLAN) ExpireAdj(sysid clns.SystemID) {
	link.expireC <- sysid
}

// -------------------
// Adjacency Functions
// -------------------

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
		debug(DbgFFlags, "%s: Real set of %s for %s", link, flag, *lspid)
		link.flags[flag][*lspid] = struct{}{}
	} else {
		debug(DbgFFlags, "%s: Real clear of %s for %s", link, flag, *lspid)
		delete(link.flags[flag], *lspid)
	}
}

func (link *LinkLAN) waitFlags() {
	// XXX add a timer/ticker here to handle LSP flood pacing.
	debug(DbgFFlags, "%s: Waiting for flag changes", link)
	select {
	case cf := <-link.flagsC:
		link.changeFlag(cf.flag, cf.set, &cf.lspid)
	}
}

func (link *LinkLAN) gatherFlags() uint {
	for count := uint(0); ; count++ {
		select {
		case cf := <-link.flagsC:
			link.changeFlag(cf.flag, cf.set, &cf.lspid)
		default:
			return count
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
			debug(DbgFFlags, "%s SENDING LSP %s", link, lspid)
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
		count := link.gatherFlags() + 1
		debug(DbgFFlags, "%s Gathered %d flags", link, count)
		for len(link.flags[SRM]) != 0 || len(link.flags[SSN]) != 0 {
			link.sendAllPSNP()
			link.sendAnLSP()
		}
	}
}
