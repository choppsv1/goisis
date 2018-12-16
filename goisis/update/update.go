// -*- coding: utf-8 -*-
//
// November 20 2018, Christian Hopps <chopps@gmail.com>

// Package update implements the update process of the IS-IS routing protocol.
// This file contains the external API and the go routine for the update
// process.
package update

import (
	"bytes"
	"fmt"
	"github.com/choppsv1/goisis/clns"
	"github.com/choppsv1/goisis/pkt"
	xtime "github.com/choppsv1/goisis/time"
	"github.com/choppsv1/goisis/tlv"
	"net"
	"os"
	"time"
)

// LSPCreateGenDelay is the initial delay for our non-pnode LSP
const LSPCreateGenDelay = 10 * time.Second

// LSPGenDelay is the delay used to try and gather multiple chaanges before advertising
const LSPGenDelay = 100 * time.Millisecond

// ==========
// Interfaces
// ==========

// Circuit is the interface that update requires for circuits.
type Circuit interface {
	IsP2P() bool
	ChgFlag(SxxFlag, *clns.LSPID, bool, clns.LIndex)
	Addrs(v4, linklocal bool) []net.IPNet
	CID(clns.LIndex) uint8
	Name() string
}

// =====
// Types
// =====

// DB holds all LSP for a given level.
type DB struct {
	sysid     clns.SystemID  // change to public as immutable
	istype    clns.LevelFlag // change to public as immutable
	li        clns.LIndex    // change to public as immutable
	areas     [][]byte
	nlpid     []byte
	hostname  string
	circuits  map[string]Circuit
	dis       map[uint8]disInfo
	chgCC     chan chgCircuit
	chgDISC   chan chgDIS
	chgLSPC   chan chgLSP
	csnpTickC chan uint8
	expireC   chan clns.LSPID
	refreshC  chan clns.LSPID
	dataC     chan interface{}
	pduC      chan inputPDU
	db        map[clns.LSPID]*lspSegment
	ownlsp    map[uint8]*OwnLSP
	debug     func(string, ...interface{})
}

func (db *DB) String() string {
	return fmt.Sprintf("UpdateDB(%s)", db.li)
}

type chgCircuit struct {
	c    Circuit // nil for remove.
	name string
}

type chgDIS struct {
	c   Circuit // nil for resign.
	cid uint8   // circuit ID
}

type chgLSP struct {
	pnid  uint8
	timer bool
}

// ErrLSP is a general error in LSP packet processing
type ErrLSP string

func (e ErrLSP) Error() string {
	return fmt.Sprintf("ErrLSP: %s", string(e))
}

// inputPDU is the PDU input to the udpate process
type inputPDU struct {
	c       Circuit // nil is internal originated.
	payload []byte
	pdutype clns.PDUType
	tlvs    map[tlv.Type][]tlv.Data
}

// inputGetLSP is the input to db.getlspC channel
type inputGetLSP struct {
	lspid   *clns.LSPID
	payload []byte
	result  chan int
}

// inputGetSNP is the input to db.getsnpC channel
type inputGetSNP struct {
	lspid  *clns.LSPID
	ent    []byte
	result chan bool
}

// lspSegment represents an LSP segment from an IS.
type lspSegment struct {
	payload  []byte
	hdr      []byte
	tlvs     map[tlv.Type][]tlv.Data
	lspid    clns.LSPID
	life     *xtime.HoldTimer
	zeroLife *xtime.HoldTimer
	refresh  *time.Timer
	// XXX isAck    bool
	isOurs bool
}

type lspCompareResult int

// Constant values for lspCompareResult
const (
	OLDER lspCompareResult = -1
	SAME                   = 0
	NEWER                  = 1
)

func (result lspCompareResult) String() string {
	switch {
	case result < 0:
		return "OLDER"
	case result > 0:
		return "NEWER"
	default:
		return "SAME"
	}
}

// disInfo is used to track state for DIS (CSNP)
type disInfo struct {
	c       Circuit
	startID clns.LSPID
	timer   *time.Timer
}

// NewDB returns a new Update Process LSP database
func NewDB(sysid []byte, istype clns.LevelFlag, l clns.Level, areas [][]byte, nlpid []byte, debug func(string, ...interface{})) *DB {
	db := &DB{
		istype:    istype,
		li:        l.ToIndex(),
		areas:     areas,
		nlpid:     nlpid,
		hostname:  "",
		circuits:  make(map[string]Circuit),
		chgLSPC:   make(chan chgLSP, 10),
		chgCC:     make(chan chgCircuit, 10),
		chgDISC:   make(chan chgDIS, 10),
		debug:     debug,
		dis:       make(map[uint8]disInfo),
		db:        make(map[clns.LSPID]*lspSegment),
		ownlsp:    make(map[uint8]*OwnLSP),
		expireC:   make(chan clns.LSPID, 10),
		refreshC:  make(chan clns.LSPID, 10),
		csnpTickC: make(chan uint8, 10),
		dataC:     make(chan interface{}, 10),
		pduC:      make(chan inputPDU, 10),
	}

	if h, err := os.Hostname(); err != nil {
		db.debug("WARNING: Error getting hostname: %s", err)
	} else {
		db.hostname = h
	}

	// Create our own LSP
	db.ownlsp[0] = NewOwnLSP(0, db, nil)

	copy(db.sysid[:], sysid)
	go db.run()

	return db
}

// ============
// External API
// ============

// Slicer grabs a slice from a byte slice given a start and length.
func Slicer(b []byte, start int, length int) []byte {
	return b[start : start+length]
}

// InputLSP creates or updates an LSP in the update DB after validity checks.
func (db *DB) InputLSP(c Circuit, payload []byte, pdutype clns.PDUType, tlvs map[tlv.Type][]tlv.Data) error {

	// ------------------------------------------------------------
	// ISO10589: 7.3.15.1.a "Action on receipt of a link state PDU"
	// ------------------------------------------------------------

	// 1-5 already done in receive
	// 6 Check SNPA from an adj (use function)
	// 7/8 check password/auth

	// Check the length
	if len(payload) > clns.LSPOrigBufSize {
		s := fmt.Sprintf("TRAP: corruptedLSPReceived: %s len %d", c, len(payload))
		db.debug(s)
		return ErrLSP(s)
	}

	// Check the checksum
	lspbuf := payload[clns.HdrCLNSSize:]
	if pkt.GetUInt16(lspbuf[clns.HdrLSPLifetime:]) != 0 {
		cksum := clns.Cksum(lspbuf[4:], 0)
		if cksum != 0 {
			fcksum := pkt.GetUInt16(lspbuf[clns.HdrLSPCksum:])
			s := fmt.Sprintf("TRAP corruptedLSPReceived: %s got 0x%04x expect 0x%04x dropping", c, cksum, fcksum)
			db.debug(s)
			return ErrLSP(s)
		}
	}

	// 9)
	btlv := tlvs[tlv.TypeLspBufSize]
	if btlv != nil {
		if len(btlv) != 1 {
			s := fmt.Sprintf("INFO: Incorrect LSPBufSize TLV count: %d", len(btlv))
			db.debug(s)
			return ErrLSP(s)
		}
		val, err := btlv[0].LSPBufSizeValue()
		if err != nil {
			db.debug("XXX: LSPBufSizeValue error: %s", err)
			return err
		}
		if val != clns.LSPOrigBufSize {
			s := fmt.Sprintf("TRAP: originatingLSPBufferSizeMismatch: %d", val)
			db.debug(s)
			return ErrLSP(s)
		}
	}

	// Finish the rest in our update process go routine (avoid locking)

	var lspid clns.LSPID
	copy(lspid[:], payload[clns.HdrCLNSSize+clns.HdrLSPLSPID:])
	db.debug("%s: Channeling LSP %s from %s to Update Process", db, lspid, c)

	db.pduC <- inputPDU{c, payload, pdutype, tlvs}
	return nil
}

// InputSNP creates or updates an LSP in the update DB after validity checks.
func (db *DB) InputSNP(c Circuit, payload []byte, pdutype clns.PDUType, tlvs map[tlv.Type][]tlv.Data) error {

	// -------------------------------------------------------------
	// ISO10589: 7.3.15.2 "Action on receipt of sequence numbers PDU
	// -------------------------------------------------------------
	// a.1-5 already done in receive 6 Check SNPA from an adj (use function)
	// a.[78] check password/auth

	db.debug("%s: Channeling SNP from %s to Update Process", db, c)
	db.pduC <- inputPDU{c, payload, pdutype, tlvs}
	return nil
}

// AddCircuit informs the update process of a new circuit.
func (db *DB) AddCircuit(c Circuit) {
	db.chgCC <- chgCircuit{c: c, name: c.Name()}
}

// RemoveCircuit removes a circuit from the update process
func (db *DB) RemoveCircuit(c Circuit) {
	db.chgCC <- chgCircuit{c: nil, name: c.Name()}
}

// ElectDIS sets or clears if we are DIS for the circuit ID.
func (db *DB) ElectDIS(c Circuit, cid uint8) {
	db.chgDISC <- chgDIS{c, cid}
}

// ResignDIS inform UP that we have resigned DIS for the circuit ID.
func (db *DB) ResignDIS(cid uint8) {
	db.chgDISC <- chgDIS{nil, cid}
}

// SomethingChanged indicate to the update process that something changed, if
// 'c' is non-nil then it relates to the circuit otherwise the router.
func (db *DB) SomethingChanged(c Circuit) {
	if c == nil {
		db.chgLSPC <- chgLSP{}
	} else {
		cid := c.CID(db.li)
		db.chgLSPC <- chgLSP{pnid: cid}
	}
}

// CopyLSPPayload copies the LSP payload buffer for sending if found and returns
// the count of copied bytes, otherwise returns 0.
func (db *DB) CopyLSPPayload(lspid *clns.LSPID, payload []byte) int {
	result := make(chan int, 1)
	db.dataC <- inputGetLSP{lspid, payload, result}
	l := <-result
	close(result)
	return l
}

// CopyLSPSNP copies the lspSegment SNP data if found and return true, else false
func (db *DB) CopyLSPSNP(lspid *clns.LSPID, ent []byte) bool {
	result := make(chan bool, 1)
	db.dataC <- inputGetSNP{lspid, ent, result}
	found := <-result
	close(result)
	return found
}

// ===========================================================
// Internal Functionality only called in the update go routine
// ===========================================================

// String returns a string identifying the LSP DB lock must be held
func (lsp *lspSegment) String() string {
	return fmt.Sprintf("LSP(id:%s seqno:%#08x holdtimer:%v lifetime:%v cksum:%#04x)",
		clns.ISOString(lsp.lspid[:], false),
		lsp.seqNo(),
		lsp.checkLifetime(),
		pkt.GetUInt16(lsp.hdr[clns.HdrLSPLifetime:]),
		lsp.cksum())
}

// setAllFlag sets flag for LSPID on all circuits but 'not' for updb level.
func (db *DB) setAllFlag(flag SxxFlag, lspid *clns.LSPID, not Circuit) {
	for _, c := range db.circuits {
		if c != not {
			c.ChgFlag(flag, lspid, true, db.li)
		}
	}
}

// clearAllFlag clears flag for LSPID on all circuits but 'not' for updb level.
func (db *DB) clearAllFlag(flag SxxFlag, lspid *clns.LSPID, not Circuit) {
	for _, c := range db.circuits {
		if c != not {
			c.ChgFlag(flag, lspid, false, db.li)
		}
	}
}

// setFlag sets flag for LSPID on circuit for the updb level.
func (db *DB) setFlag(flag SxxFlag, lspid *clns.LSPID, c Circuit) {
	// May be called with nil if the LSP is internal originated
	if c != nil {
		c.ChgFlag(flag, lspid, true, db.li)
	}
}

// clearFlag clears flag for LSPID on circuit for the updb level.
func (db *DB) clearFlag(flag SxxFlag, lspid *clns.LSPID, c Circuit) {
	// May be called with nil if the LSP is internal originated
	if c != nil {
		c.ChgFlag(flag, lspid, false, db.li)
	}
}

func (db *DB) addrs(v4 bool) []net.IPNet {
	addrs := make([]net.IPNet, 0, len(db.circuits))
	for _, c := range db.circuits {
		for _, addr := range c.Addrs(v4, false) {
			addrs = append(addrs, addr)
		}
	}
	return addrs
}

func (db *DB) isOwnSupported(lspid clns.LSPID) bool {
	isOurs := bytes.Equal(lspid[:clns.SysIDLen], db.sysid[:])
	if !isOurs {
		return false
	}

	pnid := lspid[clns.SysIDLen]
	segid := lspid[clns.NodeIDLen]
	return db.ownlsp[pnid] != nil && db.ownlsp[pnid].segments[segid] != nil
}

func (db *DB) handleExpireC(lspid clns.LSPID) {
	db.debug("1) <-expireC %s", lspid)
	// Come in here 2 ways, either with zeroLifetime non-nil but
	// expired in which case we should be good to remove, or nil
	// b/c the hold timer fired for this LSP.
	lsp, ok := db.db[lspid]
	if !ok {
		// it's gone we're done.
		db.debug("Warning: <-expireC %s not present", lspid)
		return
	}

	// Let's do a sanity check and make sure this isn't our own LSP that we support.
	if db.isOwnSupported(lspid) {
		db.debug("<-expireC: %s Expired without refresh! (timer: %v)", lsp, lsp.refresh != nil)
		if lsp.refresh != nil {
			lsp.refresh.Stop()
			lsp.refresh = nil
		}
		db.debug("<-expireC: %s Expired without refresh increment", lsp)
		db.incSeqNo(lsp.payload, lsp.seqNo())
		return
	}

	db.debug("2) <-expireC %s", lspid)
	if lsp.life != nil {
		if lsp.life.Until() != 0 {
			db.debug("<-expireC: %s ressurected", lsp)
			return
		}
		// Done with timer.
		lsp.life = nil
	}
	db.debug("3) <-expireC %s", lspid)
	if pkt.GetUInt32(lsp.hdr[clns.HdrLSPSeqNo:]) == 0 {
		db.debug("Deleting Zero-SeqNo LSP %s", lspid)
		delete(db.db, lsp.lspid)
	} else if lsp.zeroLife == nil {
		db.debug("4) <-expireC %s", lspid)
		db.initiatePurgeLSP(lsp, true)
	} else {
		db.debug("5) <-expireC %s", lspid)
		// Purge complete
		if lsp.life != nil {
			panic("Non-zero lifetime in zero max age")
		}
		db.debug("6) <-expireC %s", lspid)
		if lsp.zeroLife.Until() != 0 {
			db.debug("<-expireC: zeroLife %s ressurected", lsp)
		} else {
			lsp.zeroLife = nil
			db.debug("Deleting LSP %s", lsp)
			delete(db.db, lsp.lspid)
		}
		db.debug("7) <-expireC %s", lspid)
	}
	db.debug("8) <-expireC %s", lspid)
}

// handleRefreshC handles timer events to refresh one of our LSP segments
func (db *DB) handleRefreshC(in clns.LSPID) {
	dblsp := db.db[in]
	if !db.isOwnSupported(in) {
		lifetime := dblsp.checkLifetime()
		if lifetime != 0 {
			panic(fmt.Sprintf("%s: Non-zero lifetime unsupported own LSP %s %d", db, dblsp, lifetime))
		}
		// We do not refresh purged LSP segments, just drop this timer
		// event, this can happen if we can't stop the timer when we
		// initiate a purge.
		return
	}
	db.incSeqNo(dblsp.payload, dblsp.seqNo())
}

// handleChgLSPC handles changes to our Own LSPs
func (db *DB) handleChgLSPC(in chgLSP) {
	lsp := db.ownlsp[in.pnid]
	if lsp == nil {
		return
	}

	// This is our regen wait timer, regen now.
	if in.timer {
		lsp.regenWait = nil
		_ = lsp.regenLSP() // nolint
		return
	}

	// If we are already waiting we are done.
	if lsp.regenWait != nil {
		return
	}

	delay := time.Millisecond * 100
	lsp.regenWait = time.AfterFunc(delay,
		func() { db.chgLSPC <- chgLSP{timer: true, pnid: in.pnid} })
}

// inputPDU handles one PDU from our pdu channel
func (db *DB) handlePduC(in *inputPDU) {
	switch in.pdutype {
	case clns.PDUTypeLSPL1, clns.PDUTypeLSPL2:
		db.receiveLSP(in.c, in.payload, in.tlvs)
	case clns.PDUTypeCSNPL1, clns.PDUTypeCSNPL2:
		db.receiveSNP(in.c, true, in.payload, in.tlvs)
	case clns.PDUTypePSNPL1, clns.PDUTypePSNPL2:
		db.receiveSNP(in.c, false, in.payload, in.tlvs)
	default:
		panic(fmt.Sprintf("%s: unexpected PDU type %s", db, in.pdutype))
	}

}

func (db *DB) handleDataC(req interface{}) {
	switch in := req.(type) {
	case inputGetSNP:
		lsp, ok := db.db[*in.lspid]
		if !ok {
			in.result <- false
			break
		}
		lsp.getUpdLifetime(true)
		copy(in.ent, lsp.hdr[clns.HdrLSPLifetime:clns.HdrLSPFlags])
		in.result <- true
	case inputGetLSP:
		lsp, ok := db.db[*in.lspid]
		if !ok {
			in.result <- 0
			break
		}
		lsp.getUpdLifetime(true)
		in.result <- copy(in.payload, lsp.payload)
	default:
		panic(fmt.Sprintf("%s: unexpected GetDataC value %v", db, in))
	}
}

func (db *DB) handleChgDISC(in chgDIS) {
	db.debug("%s: handle DIS change in: %v", db, in)

	di, wasSet := db.dis[in.cid]
	if wasSet && di.c == in.c {
		db.debug("%s: No DIS change c: %v in: %v", db, di.c, in)
		return
	}

	// Update our non-pnode LSP
	db.SomethingChanged(nil)

	elected := in.c != nil
	if !wasSet && !elected {
		// Indicate elected but not us.
		db.dis[in.cid] = disInfo{}
		db.debug("%s: No DIS set and we aren't elected on CID %d", db, in.cid)
		return
	}
	if elected {
		c := in.c
		db.debug("%s: Elected DIS on %s", db, c.Name())

		// Start sending CSNP
		// XXX csnp interval hardcoded here.
		db.dis[in.cid] = disInfo{
			c: in.c,
			timer: time.AfterFunc(time.Second*10, func() {
				db.csnpTickC <- in.cid
			}),
		}

		db.ownlsp[in.cid] = NewOwnLSP(in.cid, db, c)
	} else {
		// Stop the CSNP timer.
		if di.timer != nil {
			di.timer.Stop()
		}
		c := di.c

		db.dis[in.cid] = disInfo{}

		db.debug("%s: Resigned DIS on %s", db, c.Name())
		lsp := db.ownlsp[in.cid]
		db.ownlsp[in.cid] = nil
		lsp.purge()

		// Stop sending CSNP
	}
}

// Send a CSNP packet on the circuit.
func (db *DB) handleCsnpTickC(in uint8) {
	di, ok := db.dis[in]
	if !ok || di.c == nil {
		return
	}
	// XXX fill a CSNP PDU here.
}

// Run runs the update process
// nolint: gocyclo
func (db *DB) run() {

	for {
		select {
		case in := <-db.chgDISC:
			db.handleChgDISC(in)
		case in := <-db.chgLSPC:
			db.handleChgLSPC(in)
		case in := <-db.csnpTickC:
			db.handleCsnpTickC(in)
		case in := <-db.pduC:
			db.handlePduC(&in)
		case in := <-db.expireC:
			db.handleExpireC(in)
		case in := <-db.refreshC:
			db.handleRefreshC(in)
		case in := <-db.dataC:
			db.handleDataC(in)
		case in := <-db.chgCC:
			if in.c != nil {
				db.circuits[in.name] = in.c
			} else {
				delete(db.circuits, in.name)
			}
		}
	}
}
