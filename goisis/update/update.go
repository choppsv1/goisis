// Package update implements the update process (flooding)
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
	"sort"
	"time"
)

// Delays for own LSP gen..
const LSPCreateGenDelay = 10 * time.Second
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
	sysid    clns.SystemID // change to public as immutable
	areas    [][]byte
	nlpid    []byte
	istype   clns.LevelFlag // change to public as immutable
	li       clns.LIndex    // change to public as immutable
	hostname string
	circuits map[string]Circuit
	dis      map[uint8]Circuit
	chgCC    chan chgCircuit
	chgDISC  chan chgDIS
	chgLSPC  chan chgLSP
	expireC  chan clns.LSPID
	refreshC chan clns.LSPID
	dataC    chan interface{}
	pduC     chan inputPDU
	db       map[clns.LSPID]*lspSegment
	ownlsp   map[uint8]*OwnLSP
	debug    func(string, ...interface{})
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

// ErrIIH is a general error in IIH packet processing
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
	isAck    bool
	isOurs   bool
}

type lspCompareResult int

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

// NewDB returns a new Update Process LSP database
func NewDB(sysid []byte, istype clns.LevelFlag, l clns.Level, areas [][]byte, nlpid []byte, debug func(string, ...interface{})) *DB {
	db := &DB{
		istype:   istype,
		li:       l.ToIndex(),
		areas:    areas,
		nlpid:    nlpid,
		hostname: "",
		circuits: make(map[string]Circuit),
		chgLSPC:  make(chan chgLSP, 10),
		chgCC:    make(chan chgCircuit, 10),
		chgDISC:  make(chan chgDIS, 10),
		debug:    debug,
		dis:      make(map[uint8]Circuit),
		db:       make(map[clns.LSPID]*lspSegment),
		ownlsp:   make(map[uint8]*OwnLSP),
		expireC:  make(chan clns.LSPID, 10),
		refreshC: make(chan clns.LSPID, 10),
		dataC:    make(chan interface{}, 10),
		pduC:     make(chan inputPDU, 10),
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

func (db *DB) AddCircuit(c Circuit) {
	db.chgCC <- chgCircuit{c: c, name: c.Name()}
}

func (db *DB) RemoveCircuit(c Circuit) {
	db.chgCC <- chgCircuit{c: nil, name: c.Name()}
}

// SetDIS sets or clears if we are DIS for the circuit ID.
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

// Slicer grabs a slice from a byte slice given a start and length.
func Slicer(b []byte, start int, length int) []byte {
	return b[start : start+length]
}

func (lsp *lspSegment) seqNo() uint32 {
	return pkt.GetUInt32(lsp.hdr[clns.HdrLSPSeqNo:])
}

func (lsp *lspSegment) checkLifetime() uint16 {
	if lsp.life == nil {
		return 0
	}
	return lsp.life.Until()
}

func (lsp *lspSegment) getUpdLifetime(shave bool) uint16 {
	if lsp.life == nil {
		if pkt.GetUInt16(lsp.hdr[clns.HdrLSPLifetime:]) != 0 {
			panic("Invalid non-zero life with no holdtimer")
		}
		return 0
	}
	lifetime := lsp.life.Until()
	// This is to test flooding
	// if shave {
	// 	if lifetime > 15 {
	// 		lifetime -= 15
	// 	}
	// }
	pkt.PutUInt16(lsp.hdr[clns.HdrLSPLifetime:], lifetime)
	return lifetime
}

func (lsp *lspSegment) setLifetime(sec uint16) {
	pkt.PutUInt16(lsp.hdr[clns.HdrLSPLifetime:], sec)
}

func (lsp *lspSegment) cksum() uint16 {
	return pkt.GetUInt16(lsp.hdr[clns.HdrLSPCksum:])
}

// func (lsp *lspSegment) getFlags() clns.LSPFlags {
// 	return clns.LSPFlags(lsp.hdr[clns.HdrLSPFlags])
// }

// newLSPSegment creates a new lspSegment struct
func (db *DB) newLSPSegment(payload []byte, tlvs map[tlv.Type][]tlv.Data) *lspSegment {
	hdr := Slicer(payload, clns.HdrCLNSSize, clns.HdrLSPSize)
	lsp := &lspSegment{
		payload: payload,
		hdr:     hdr,
		tlvs:    tlvs,
	}
	copy(lsp.lspid[:], hdr[clns.HdrLSPLSPID:])

	lifetime := pkt.GetUInt16(hdr[clns.HdrLSPLifetime:])
	// // XXX testing
	// lifetime = 30
	lsp.life = xtime.NewHoldTimer(lifetime, func() { db.expireC <- lsp.lspid })
	lsp.isOurs = bytes.Equal(lsp.lspid[:clns.SysIDLen], db.sysid[:])
	// // We aren't locked but this isn't in the DB yet.
	// if lsp.isOurs {
	//      lsp.refreshTimer = time.NewTimer(lsp.lifetime.Remainingg())
	// }

	db.db[lsp.lspid] = lsp

	db.debug("%s: New LSP: %s", db, lsp)
	return lsp
}

// newLSPSegment creates a new lspSegment struct
func (db *DB) newZeroLSPSegment(lifetime uint16, lspid *clns.LSPID, cksum uint16) *lspSegment {
	lsp := &lspSegment{
		hdr: make([]byte, clns.HdrLSPSize),
	}
	lsp.lspid = *lspid
	copy(lsp.hdr[clns.HdrLSPLSPID:], lsp.lspid[:])
	pkt.PutUInt16(lsp.hdr[clns.HdrLSPLifetime:], lifetime)
	pkt.PutUInt16(lsp.hdr[clns.HdrLSPCksum:], cksum)
	lsp.life = xtime.NewHoldTimer(lifetime, func() { db.expireC <- lsp.lspid })
	lsp.isOurs = bytes.Equal(lsp.lspid[:clns.SysIDLen], db.sysid[:])

	db.db[lsp.lspid] = lsp

	db.debug("%s: New Zero SeqNo LSP: %s", db, lsp)
	return lsp
}

// updateLSPSegment updates an lspSegment with a newer version received on a link.
func (db *DB) updateLSPSegment(lsp *lspSegment, payload []byte, tlvs map[tlv.Type][]tlv.Data) {
	if db.debug != nil {
		db.debug("%s: Updating %s", db, lsp)
	}

	// On entering the hold timer has already been stopped by receiveLSP

	// if lsp.isOurs {
	// 	pnid := lsp.lspid[7]
	// }

	// We are replacing the previous PDU payload slice thus we are
	// relinquishing our reference on that previous PDU frame
	lsp.payload = payload
	lsp.hdr = Slicer(payload, clns.HdrCLNSSize, clns.HdrLSPSize)
	lsp.tlvs = tlvs

	lifetime := pkt.GetUInt16(lsp.hdr[clns.HdrLSPLifetime:])
	if lifetime == 0 {
		if lsp.life != nil {
			// Timer is stopped. Forget about it.
			lsp.life = nil
		}
		if lsp.zeroLife == nil {
			// New purge.
			db.debug("%s: Received Purge LSP %s", db, lsp)
			lsp.zeroLife = xtime.NewHoldTimer(clns.ZeroMaxAge,
				func() { db.expireC <- lsp.lspid })
		} else if lsp.zeroLife.Until() < clns.ZeroMaxAge {
			// Refresh zero age. If we can't reset the timer b/c
			// it's fired/firing just create a new one. We handle it.
			if !lsp.zeroLife.Stop() {
				lsp.zeroLife = xtime.NewHoldTimer(clns.ZeroMaxAge,
					func() { db.expireC <- lsp.lspid })
			} else {
				lsp.zeroLife.Reset(clns.ZeroMaxAge)
			}
		}
		return
	}

	if lsp.life != nil {
		// Reset the hold timer -- XXX are we always supposed to do this?
		lsp.life.Reset(lifetime)
		db.debug("%s: Reset hold timer %d for %s", db, lifetime, lsp)
	} else {
		// We should never see both nil we would have deleted it.
		if lsp.zeroLife == nil {
			panic(fmt.Sprintf("WARNING: both life and zeroLife nil for %s", lsp))
		}
		// No need to check if we sotpped as we can handle being
		// called now after update.
		lsp.zeroLife.Stop()
		lsp.zeroLife = nil
		lsp.life = xtime.NewHoldTimer(lifetime, func() { db.expireC <- lsp.lspid })
		db.debug("%s: Reset hold timer for Purged %s", db, lsp)
	}

	// XXX update refresh timer?
	// if lsp.isOurs {
	//      // assert(lsp.refreshTimer != nil)
	//      timeleft := lifetime * 3 / 4
	//      // assert timeleft
	//      if !lsp.refreshTimer.Stop() {
	//              <-lsp.refreshTimer.C
	//      }
	//      lsp.refreshTimer.Reset(timeleft)
	// }

	db.debug("%s: Updated %s", db, lsp)
}

// initiatePurgeLSP initiates a purge of an LSPSegment due to lifetime running
// to zero.
func (db *DB) initiatePurgeLSP(lsp *lspSegment, fromTimer bool) {
	var zeroMaxAge uint16

	// If we still have a timer still stop it if we can.
	if lsp.life == nil {
		zeroMaxAge = clns.ZeroMaxAge
	} else {
		if !fromTimer && !lsp.life.Stop() {
			// Can't stop the timer we will be called again.
			db.debug("%s: Can't stop timer for %s let it happen", db, lsp)
			return
		}
		// We hold on to LSPs that we force purge longer.
		zeroMaxAge = clns.MaxAge
		lsp.life = nil
	}

	// Get rid of refresh timer for our own LSP segments.
	if lsp.refresh != nil {
		lsp.refresh.Stop()
		lsp.refresh = nil
	}

	// Update the lifetime to zero if it wasn't already.
	pkt.PutUInt16(lsp.hdr[clns.HdrLSPLifetime:], 0)
	db.debug("%s: Purging %s zeroMaxAge: %d", db, lsp, zeroMaxAge)

	if lsp.zeroLife != nil {
		panic("Initiating a purge on a purged LSP.")
	}
	lsp.zeroLife = xtime.NewHoldTimer(zeroMaxAge,
		func() { db.expireC <- lsp.lspid })

	//-----------------------------
	// ISO10589: 7.3.16.4: a, b, c
	//-----------------------------

	// a)
	// db.setsrm <- lsp.lspid
	db.setAllFlag(SRM, &lsp.lspid, nil)

	// b) Retain only LSP header. XXX we need more space for auth and purge tlv
	pdulen := uint16(clns.HdrCLNSSize + clns.HdrLSPSize)
	db.debug("Shrinking lsp.payload %d:%d to %d", len(lsp.payload), cap(lsp.payload), pdulen)
	lsp.payload = lsp.payload[:pdulen]
	db.debug("Shrunk lsp.payload to %d:%d", len(lsp.payload), cap(lsp.payload))
	pkt.PutUInt16(lsp.hdr[clns.HdrLSPCksum:], 0)
	pkt.PutUInt16(lsp.hdr[clns.HdrLSPPDULen:], pdulen)
}

// Increment the sequence number for one of our own LSP segments, fixup the
// header and inject into DB.
func (db *DB) incSeqNo(payload []byte, seqno uint32) {
	db.debug("%s Incrementing Own Seq No 0x%x", db, seqno)

	lspbuf := payload[clns.HdrCLNSSize:]

	seqno += 1 // XXX deal with rollover.

	lifetime := uint16(clns.MaxAge)
	pkt.PutUInt16(lspbuf[clns.HdrLSPLifetime:], lifetime)
	pkt.PutUInt32(lspbuf[clns.HdrLSPSeqNo:], seqno)
	pkt.PutUInt16(lspbuf[clns.HdrLSPCksum:], 0)
	cksum := clns.Cksum(lspbuf[clns.HdrLSPLSPID:], 13)
	pkt.PutUInt16(lspbuf[clns.HdrLSPCksum:], cksum)

	tlvs, err := tlv.Data(lspbuf[clns.HdrLSPSize:]).ParseTLV()
	if err != nil {
		db.debug("%s Invalid TLV from ourselves", db)
		panic("Invalid TLV from ourselves")
	}

	db.receiveLSP(nil, payload, tlvs)
}

// compareLSP we compare against either the LSP header + 2 or an SNPEntry.
func compareLSP(lsp *lspSegment, e []byte) lspCompareResult {
	if lsp == nil {
		return NEWER
	}

	// Do a quick check to see if this is the same memory.
	if tlv.GetOffset(lsp.payload[clns.HdrCLNSSize+clns.HdrLSPLifetime:], e) == 0 {
		return SAME
	}

	nseqno := pkt.GetUInt32(e[tlv.SNPEntSeqNo:])
	oseqno := lsp.seqNo()
	if nseqno > oseqno {
		return NEWER
	} else if nseqno < oseqno {
		return OLDER
	}

	nlifetime := pkt.GetUInt16(e[tlv.SNPEntLifetime:])
	olifetime := lsp.getUpdLifetime(false)
	if nlifetime == 0 && olifetime != 0 {
		return NEWER
	} else if olifetime == 0 && nlifetime != 0 {
		return OLDER
	}
	return SAME
}

// receiveLSP receives an LSP from flooding
func (db *DB) receiveLSP(c Circuit, payload []byte, tlvs map[tlv.Type][]tlv.Data) {
	// We input or own LSP here with nil circuit to differentiate.
	fromUs := c == nil

	var lspid clns.LSPID
	copy(lspid[:], payload[clns.HdrCLNSSize+clns.HdrLSPLSPID:])

	lsp := db.db[lspid]

	newhdr := Slicer(payload, clns.HdrCLNSSize, clns.HdrLSPSize)
	nlifetime := pkt.GetUInt16(newhdr[clns.HdrLSPLifetime:])
	nseqno := pkt.GetUInt32(newhdr[clns.HdrLSPSeqNo:])

	result := compareLSP(lsp, newhdr[clns.HdrLSPLifetime:])
	isOurs := bytes.Equal(lspid[:clns.SysIDLen], db.sysid[:])

	if isOurs && fromUs {
		// Force newer b/c we may have simply modified the db version of
		// the segment to increment the seqno so it won't seem newer.
		result = NEWER
	}

	db.debug("%s: receiveLSP %s 0x%x dblsp %s compare %v isOurs %v fromUs %v", db, lspid, nseqno, lsp, result, isOurs, fromUs)

	// b) If the LSP has zero Remaining Lifetime, perform the actions
	//    described in 7.3.16.4. -- for LSPs not ours this is the same as
	//    normal handling except that we do not add a missing LSP segment,
	//    instead we acknowledge receipt only.

	if isOurs && !fromUs {
		// XXX check all this.
		pnid := lsp.lspid[7]
		var unsupported bool
		if pnid == 0 {
			unsupported = false // always support non-pnode LSP
		} else {
			c, set := db.dis[pnid]
			unsupported = lsp == nil || c == nil
			if !set {
				// We haven't run dis election yet, hold off
				// on purging until we have.
				return
			}
		}

		// c) Ours, but we don't support, and not expired, perform
		//    7.3.16.4 purge. If ours not supported and expired we will
		//    simply be ACKing the receipt below under e1.
		if unsupported && nlifetime != 0 {
			if lsp != nil {
				// assert c == nil i.e., We have no circuit
				// associated with this DIS circuit ID claiming
				// to be ours.

				// Since we purge when we un-elect ourselves
				// any unsupported but present PN-LSP should be
				// purging.

				// A bad actor might inject a newer seqno for
				// our unsupported purging LSP so we need to
				// update the seqno, and purge again.
				seqno := pkt.GetUInt32(newhdr[clns.HdrLSPSeqNo:])
				if result == NEWER {
					pkt.PutUInt32(lsp.hdr[clns.HdrLSPSeqNo:], seqno)
					// Swap the zero life timer into normal
					// life to cause long zero age purge.
					if lsp.life == nil {
						lsp.life = lsp.zeroLife
						lsp.zeroLife = nil
					}
					db.initiatePurgeLSP(lsp, false)
					return
				}
			} else {
				// Create LSP and then force purge.
				lsp := db.newLSPSegment(payload, tlvs)
				// consolidate or if we need to leave for acks
				db.initiatePurgeLSP(lsp, false)
				return
			}
		}
		// d) Ours, supported and wire is newer, need to increment our
		// copy per 7.3.16.1
		if !unsupported && result == NEWER {
			db.incSeqNo(lsp.payload, nseqno)
			return
		}

	}

	// [ also: ISO 10589 17.3.16.4: a, b ]
	// e1) Newer - update db, flood and acknowledge
	//     [ also: ISO 10589 17.3.16.4: b.1 ]
	if result == NEWER && !fromUs {
		if lsp != nil && lsp.life != nil {
			if !lsp.life.Stop() {
				// This means the LSP segment just expired and we were
				// unable to stop the hold timer b/c we haven't
				// handled the event yet.  We need to recheck
				// NEWER now, it will either remain NEWER or
				// switch to SAME.
				result = compareLSP(lsp, newhdr[clns.HdrLSPLifetime:])
			} else {
				// We've now stopped the timer we would have
				// reset it anyway in updateLSPSegment.
			}
		}
	}

	if result == NEWER {
		if lsp != nil {
			if c != nil {
				db.debug("%s: Updating LSP from %s", db, c)
			} else {
				db.debug("%s: Updating Own LSP", db)
			}
			db.updateLSPSegment(lsp, payload, tlvs)
		} else {
			if c != nil {
				db.debug("%s: Added LSP from %s", db, c)
			} else {
				db.debug("%s: Added Own LSP", db)
			}
			if nlifetime == 0 {
				// 17.3.16.4: a
				// XXX send ack on circuit do not retain
				return
			}
			lsp = db.newLSPSegment(payload, tlvs)
		}

		db.setAllFlag(SRM, &lsp.lspid, c)
		db.clearFlag(SRM, &lsp.lspid, c)
		if c != nil && c.IsP2P() {
			db.setFlag(SSN, &lsp.lspid, c)
		}
		db.clearAllFlag(SSN, &lsp.lspid, c)

		// Setup/Reset a refresh time for our own LSP segments.
		if fromUs {
			if lsp.refresh != nil {
				// We don't care if we can't stop it, this pathological case
				// just results in an extra seqno increment.
				lsp.refresh.Stop()
			}
			// Refresh when the lifetime values is 3/4 expired.
			refresh := time.Second * time.Duration(nlifetime) * 3 / 4
			// New refresh timer, old one has fired, is stopped or we don't care.
			lsp.refresh = time.AfterFunc(refresh, func() { db.refreshC <- lspid })
			db.debug("%s: setting refresh timer for %s to %s", db, lsp, refresh)
		}
	} else if result == SAME {
		// e2) Same - Stop sending and Acknowledge
		//     [ also: ISO 10589 17.3.16.4: b.2 ]
		db.clearAllFlag(SRM, &lsp.lspid, nil)
		if c != nil && c.IsP2P() {
			db.setFlag(SSN, &lsp.lspid, c)
		}
	} else {
		// e3) Older - Send and don't acknowledge
		//     [ also: ISO 10589 17.3.16.4: b.3 ]
		db.setFlag(SRM, &lsp.lspid, c)
		db.clearFlag(SSN, &lsp.lspid, c)
		db.clearAllFlag(SRM, &lsp.lspid, nil)
	}
}

func (db *DB) receiveSNP(c Circuit, complete bool, payload []byte, tlvs tlv.TLVMap) {
	// -------------------------------------------------------------
	// ISO10589: 7.3.15.2 "Action on receipt of sequence numbers PDU
	// -------------------------------------------------------------
	// a.1-5 already done in receive 6 Check SNPA from an adj (use function)
	// a.[78] check password/auth

	var mentioned map[clns.LSPID]struct{}
	if complete {
		mentioned = make(map[clns.LSPID]struct{})
	}

	// ISO10589: 8.3.15.2.b
	entries, err := tlvs.SNPEntryValues()
	if err != nil {
		db.debug("%s: Error parsing SNP Entries: %s", db, err)
		return
	}

	for _, e := range entries {
		var elspid clns.LSPID
		copy(elspid[:], e[tlv.SNPEntLSPID:])
		lsp := db.db[elspid]
		mentioned[elspid] = struct{}{}

		// 7.3.15.2: b1
		result := compareLSP(lsp, e)
		switch result {
		case SAME:
			if c.IsP2P() {
				// 7.3.15.2: b2 ack received, stop sending on p2p
				db.clearFlag(SRM, &elspid, c)
			}
		case OLDER:
			// 7.3.15.2: b3 flood newer from our DB
			db.clearFlag(SSN, &elspid, c)
			db.setFlag(SRM, &elspid, c)
		case NEWER:
			lifetime := pkt.GetUInt16(e[tlv.SNPEntLifetime:])
			seqno := pkt.GetUInt32(e[tlv.SNPEntSeqNo:])
			cksum := pkt.GetUInt16(e[tlv.SNPEntCksum:])
			if lsp != nil {
				db.debug("%s: SNP Entry [life:0x%d,seqno:0x%x,cksum:0x%x] newer than LSP: %s",
					db, lifetime, seqno, cksum, lsp)

				// 7.3.15.2: b4 Request newer.
				db.setFlag(SSN, &elspid, c)
				if c.IsP2P() {
					db.clearFlag(SRM, &elspid, c)
				}
			} else {
				// 7.3.15.2: b5 Add zero seqno segment for missing
				db.debug("%s: SNP Entry [life:0x%d,seqno:0x%x,cksum:0x%x] for missing LSPID: %s",
					db, lifetime, seqno, cksum, elspid)
				if lifetime != 0 && seqno != 0 && cksum != 0 {
					_ = db.newZeroLSPSegment(lifetime, &elspid, cksum)
					db.setFlag(SSN, &elspid, c)
				}

			}
		}
	}
	if !complete {
		return
	}

	db.debug("%s: CSNP: Look for we have, they don'ts", db)

	// 7.3.15.2.c Set SRM for all LSP we have that were not mentioned.

	// Get sorted list of LSPIDs we have
	keys := make(clns.LSPIDArray, 0, len(db.db))
	for k := range db.db {
		keys = append(keys, k)
	}
	sort.Sort(keys)

	hdr := Slicer(payload, clns.HdrCLNSSize, clns.HdrCSNPSize)
	startid := Slicer(hdr, clns.HdrCSNPStartLSPID, clns.LSPIDLen)
	endid := Slicer(hdr, clns.HdrCSNPStartLSPID, clns.LSPIDLen)

	for _, lspid := range keys {
		if bytes.Compare(lspid[:], startid) < 0 {
			continue
		}
		if bytes.Compare(lspid[:], endid) > 0 {
			break
		}
		_, present := mentioned[lspid]
		if !present {
			lsp := db.db[lspid]

			db.debug("%s: CSNP: Missing %s", db, lsp)
			if lsp.seqNo() == 0 {
				db.debug("%s: CSNP: Skipping zero seqno: LSPID: %s", db, lspid)
				continue
			}
			if lsp.checkLifetime() == 0 {
				db.debug("%s: CSNP: Skipping zero lifetime: LSPID: %s", db, lspid)
				continue
			}
			db.setFlag(SRM, &lspid, c)
		}
	}

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
		lsp.regenLSP()
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
		panic(fmt.Sprintf("%s: unexpected GetDataC value %v", in))
	}
}

func (db *DB) handleChgDISC(in chgDIS) {
	db.debug("%s: handle DIS change in: %v", db, in)

	c, wasSet := db.dis[in.cid]

	db.debug("%s: handleChgDIS 1", db)

	db.dis[in.cid] = in.c

	db.debug("%s: handleChgDIS 2", db)

	if wasSet && c == in.c {
		db.debug("%s: No DIS change c: %v in: %v", db, c, in)
		return
	}

	db.debug("%s: handleChgDIS 3", db)

	// Update our non-pnode LSP
	db.SomethingChanged(nil)

	db.debug("%s: handleChgDIS 4", db)

	elected := in.c != nil

	db.debug("%s: handleChgDIS 5", db)

	if !wasSet && !elected {
		db.debug("%s: No DIS set and we aren't elected on %s", db, c)
		return
	}

	db.debug("%s: handleChgDIS 6", db)

	if elected {
		c := in.c
		db.debug("%s: Elected DIS on %s", db, c.Name())
		db.ownlsp[in.cid] = NewOwnLSP(in.cid, db, c)
	} else {
		db.debug("%s: Resigned DIS on %s", db, c.Name())
		lsp := db.ownlsp[in.cid]
		db.ownlsp[in.cid] = nil
		lsp.purge()
	}
}

// Run runs the update process
func (db *DB) run() {

	for {
		select {
		case in := <-db.chgDISC:
			db.handleChgDISC(in)
		case in := <-db.chgLSPC:
			db.handleChgLSPC(in)
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
