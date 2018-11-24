// Package update implements the update process (flooding)
package update

import (
	"bytes"
	"fmt"
	"github.com/choppsv1/goisis/clns"
	"github.com/choppsv1/goisis/pkt"
	xtime "github.com/choppsv1/goisis/time"
	"github.com/choppsv1/goisis/tlv"
)

// ==========
// Interfaces
// ==========

// Circuit is the interface that update requires for circuits.
type Circuit interface {
	ClearFlag(flag SxxFlag, lspid *clns.LSPID, li clns.LIndex)
	SetFlag(flag SxxFlag, lspid *clns.LSPID, li clns.LIndex)
	IsP2P() bool
}

// =====
// Types
// =====

// DB holds all LSP for a given level.
type DB struct {
	sysid   clns.SystemID
	dis     [256]Trit
	disC    chan chgDIS
	lspC    chan inputPDU
	flagsC  chan<- ChgSxxFlag
	getlspC chan inputGetLSP
	getsnpC chan inputGetSNP
	expireC chan clns.LSPID
	li      clns.LIndex
	db      map[clns.LSPID]*lspSegment
	debug   func(string, ...interface{})
}

type chgDIS struct {
	set bool  // set or clear
	cid uint8 // circuit ID
}

// ErrIIH is a general error in IIH packet processing
type ErrLSP string

func (e ErrLSP) Error() string {
	return fmt.Sprintf("ErrLSP: %s", string(e))
}

type Trit int8

func (trit Trit) String() string {
	switch trit {
	case -1:
		return "False"
	case 0:
		return "Unkonwn"
	case 1:
		return "True"
	default:
		panic("invalid trit")
	}
}
func BoolToTrit(b bool) Trit {
	if b {
		return 1
	}
	return -1
}

// inputPDU is the PDU input to the udpate process
type inputPDU struct {
	c       Circuit
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
	li       clns.LIndex
	life     *xtime.HoldTimer
	zeroLife *xtime.HoldTimer
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
func NewDB(sysid []byte, l clns.Level, flagsC chan<- ChgSxxFlag, debug func(string, ...interface{})) *DB {
	fmt.Printf("UPD: debug: %p", debug)
	db := &DB{
		debug:   debug,
		li:      l.ToIndex(),
		flagsC:  flagsC,
		db:      make(map[clns.LSPID]*lspSegment),
		lspC:    make(chan inputPDU),
		getlspC: make(chan inputGetLSP),
		getsnpC: make(chan inputGetSNP),
		expireC: make(chan clns.LSPID),
	}
	copy(db.sysid[:], sysid)
	go db.Run()

	return db
}

//
// External API no locking required.
//

// InputPDU creates or updates an LSP in the update DB after validity checks.
func (db *DB) InputLSP(c Circuit, payload []byte, pdutype clns.PDUType, tlvs map[tlv.Type][]tlv.Data) error {

	// ------------------------------------------------------------
	// ISO10589: 7.3.15.1 "Action on receipt of a link state PDU"
	// ------------------------------------------------------------

	// 1-6 already done in receive

	// Check the length
	if len(payload) > clns.LSPOrigBufSize {
		return ErrLSP(fmt.Sprintf("TRAP: corruptedLSPReceived: %s len %d",
			c, len(payload)))
	}

	// Check the checksum
	lspbuf := payload[clns.HdrCLNSSize:]
	if pkt.GetUInt16(lspbuf[clns.HdrLSPLifetime:]) != 0 {
		cksum := 0
		// cksum = iso_cksum(lspbuf[4:])
		if cksum != 0 {
			fcksum := pkt.GetUInt16(lspbuf[clns.HdrLSPCksum:])
			return ErrLSP(fmt.Sprintf("TRAP corruptedLSPReceived: %s got 0x%04x expect 0x%04x dropping", c, cksum, fcksum))
		}
	}

	// 9)
	btlv := tlvs[tlv.TypeLspBufSize]
	if btlv != nil {
		if len(btlv) != 1 {
			return ErrLSP(fmt.Sprintf("INFO: Incorrect LSPBufSize TLV count: %d", len(btlv)))
		}
		val, err := btlv[0].LSPBufSizeValue()
		if err != nil {
			return err
		}
		if val != clns.LSPOrigBufSize {
			return ErrLSP(fmt.Sprintf("TRAP: originatingLSPBufferSizeMismatch: %d", val))
		}
	}

	db.lspC <- inputPDU{c, payload, pdutype, tlvs}
	return nil
}

// SetDIS sets or clears if we are DIS for the circuit ID.
func (db *DB) SetDIS(cid uint8, set bool) {
	db.disC <- chgDIS{set, cid}
}

// CopyLSPPayload copies the LSP payload buffer for sending if found and returns
// the count of copied bytes, otherwise returns 0.
func (db *DB) CopyLSPPayload(lspid *clns.LSPID, payload []byte) int {
	result := make(chan int)
	db.getlspC <- inputGetLSP{lspid, payload, result}
	l := <-result
	close(result)
	return l
}

// CopyLSPSNP copies the lspSegment SNP data if found and return true, else false
func (db *DB) CopyLSPSNP(lspid *clns.LSPID, ent []byte) bool {
	result := make(chan bool)
	db.getsnpC <- inputGetSNP{lspid, ent, result}
	found := <-result
	close(result)
	return found
}

//
// Internal Functionality only called in the update go routine, no locking
// required.
//

// String returns a string identifying the LSP DB lock must be held
func (lsp *lspSegment) String() string {
	s := clns.ISOString(lsp.getLSPID(), false)
	return fmt.Sprintf("LSP(id:%s seqno:%#08x lifetime:%v cksum:%#04x",
		s,
		lsp.getSeqNo(),
		lsp.getUpdLifetime(),
		lsp.getCksum())
}

// SetAllFlag sets flag for LSPID on all circuits but 'not' for updb level.
func (db *DB) setAllFlag(flag SxxFlag, lspid *clns.LSPID, not Circuit) {
	db.flagsC <- ChgSxxFlag{flag, db.li, true, true, not, *lspid}
}

// ClearAllFlag clears flag for LSPID on all circuits but 'not' for updb level.
func (db *DB) clearAllFlag(flag SxxFlag, lspid *clns.LSPID, not Circuit) {
	db.flagsC <- ChgSxxFlag{flag, db.li, false, true, not, *lspid}
}

// SetFlag sets flag for LSPID on circuit for the updb level.
func (db *DB) setFlag(flag SxxFlag, lspid *clns.LSPID, c Circuit) {
	c.SetFlag(flag, lspid, db.li)
}

// ClearFlag clears flag for LSPID on circuit for the updb level.
func (db *DB) clearFlag(flag SxxFlag, lspid *clns.LSPID, c Circuit) {
	c.ClearFlag(flag, lspid, db.li)
}

// newLSPSegment creates a new lspSegment struct
func (db *DB) newLSPSegment(payload []byte, pdutype clns.PDUType, tlvs map[tlv.Type][]tlv.Data) *lspSegment {
	hdr := payload[clns.HdrCLNSSize:]
	hdr = hdr[:clns.HdrLSPSize]
	lsp := &lspSegment{
		payload: payload,
		hdr:     hdr,
		li:      pdutype.GetPDULIndex(),
		tlvs:    tlvs,
	}
	copy(lsp.lspid[:], hdr[clns.HdrLSPLSPID:])

	lifesec := pkt.GetUInt16(hdr[clns.HdrLSPLifetime:])
	// XXX testing
	lifesec = 30
	lsp.life = xtime.NewHoldTimer(lifesec, func() { db.expireC <- lsp.lspid })
	lsp.isOurs = bytes.Equal(lsp.lspid[:clns.SysIDLen], db.sysid[:])
	// // We aren't locked but this isn't in the DB yet.
	// if lsp.isOurs {
	//      lsp.refreshTimer = time.NewTimer(lsp.lifetime.Remainingg())
	// }

	db.debug("New LSP: %s", lsp)
	return lsp
}

// Slicer grabs a slice from a byte slice given a start and length.
func Slicer(b []byte, start int, length int) []byte {
	return b[start : start+length]
}

func (lsp *lspSegment) getSeqNo() uint32 {
	return pkt.GetUInt32(lsp.hdr[clns.HdrLSPSeqNo:])
}

func (lsp *lspSegment) getUpdLifetime() uint16 {
	if lsp.life == nil {
		if pkt.GetUInt16(lsp.hdr[clns.HdrLSPLifetime:]) != 0 {
			panic("Invaild non-zero life with no holdtimer")
		}
		return 0
	}
	lifetime := lsp.life.Until()
	pkt.PutUInt16(lsp.hdr[clns.HdrLSPLifetime:], lifetime)
	return lifetime
}

func (lsp *lspSegment) setLifetime(sec uint16) {
	pkt.PutUInt16(lsp.hdr[clns.HdrLSPLifetime:], sec)
}

func (lsp *lspSegment) getCksum() uint16 {
	return pkt.GetUInt16(lsp.hdr[clns.HdrLSPCksum:])
}

// func (lsp *lspSegment) getFlags() clns.LSPFlags {
// 	return clns.LSPFlags(lsp.hdr[clns.HdrLSPFlags])
// }

func (lsp *lspSegment) getLSPID() []byte {
	return lsp.hdr[clns.HdrLSPLSPID : clns.HdrLSPLSPID+clns.LSPIDLen]
}

func compareLSP(lsp *lspSegment, newhdr []byte) lspCompareResult {

	// XXX this looks bogus.
	if newhdr != nil && lsp == nil {
		return NEWER
	} else if newhdr == nil && lsp != nil {
		return OLDER
	} else if newhdr == nil && lsp == nil {
		return SAME
	}

	nseqno := pkt.GetUInt32(newhdr[clns.HdrLSPSeqNo:])
	oseqno := lsp.getSeqNo()
	if nseqno > oseqno {
		return NEWER
	} else if nseqno < oseqno {
		return OLDER
	}

	nlifetime := pkt.GetUInt16(newhdr[clns.HdrLSPLifetime:])
	olifetime := lsp.getUpdLifetime()
	if nlifetime == 0 && olifetime != 0 {
		return NEWER
	} else if olifetime == 0 && nlifetime != 0 {
		return OLDER
	}
	return SAME
}

// initiatePurgeLSP initiates a purge of an LSPSegment due to lifetime running
// to zero.
func (db *DB) initiatePurgeLSP(lsp *lspSegment) {
	var zeroMaxAge uint16

	// If we still have a timer still stop it if we can.
	if lsp.life == nil {
		zeroMaxAge = clns.ZeroMaxAge
	} else {
		if !lsp.life.Stop() {
			// Can't stop the timer we will be called again.
			return
		}
		// We hold on to LSPs that we force purge longer.
		zeroMaxAge = clns.MaxAge
		lsp.life = nil
	}

	// Update the lifetime to zero if it wasn't already.
	pkt.PutUInt16(lsp.hdr[:clns.HdrLSPLifetime], 0)
	db.debug("Lifetime for %s expired, purging.", lsp)

	if lsp.zeroLife != nil {
		panic("Initiating a purge on a purged LSP")
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
	lsp.payload = lsp.payload[:pdulen]
	pkt.PutUInt16(lsp.hdr[clns.HdrLSPCksum:], 0)
	pkt.PutUInt16(lsp.hdr[clns.HdrLSPPDULen:], pdulen)
}

// receiveLSP receives an LSP from flooding
func (db *DB) receiveLSP(c Circuit, payload []byte, pdutype clns.PDUType, tlvs map[tlv.Type][]tlv.Data) {
	var lspid clns.LSPID
	copy(lspid[:], payload[clns.HdrCLNSSize+clns.HdrLSPLSPID:])

	lsp := db.db[lspid]

	newhdr := Slicer(payload, clns.HdrCLNSSize, clns.HdrLSPSize)
	nlifetime := pkt.GetUInt16(newhdr[clns.HdrLSPLifetime:])

	result := compareLSP(lsp, newhdr)
	isOurs := bytes.Equal(lspid[:clns.SysIDLen], db.sysid[:])

	// b) If the LSP has zero Remaining Lifetime, perform the actions
	//    described in 7.3.16.4. -- for LSPs not ours this is the same as
	//    normal handling except that we do not add a missing LSP segment,
	//    instead we acknowledge receipt only.

	if isOurs {
		// XXX check all this.
		pnid := lsp.lspid[7]
		var unsupported bool
		if pnid == 0 {
			unsupported = false // always support non-pnode LSP
		} else {
			unsupported = lsp == nil || db.dis[pnid] <= 0
			if db.dis[pnid] == 0 {
				// We haven't decided who is DIS yet. We may not
				// want to purge until we have.
				// XXX
			}
		}
		// c) Ours, but we don't support, and not expired, perform
		//    7.3.16.4 purge. If ours not supported and expired we will
		//    simply be ACKing the receipt below under e1.
		if unsupported && nlifetime != 0 {
			if lsp != nil {
				// XXX check this panic out closer. XXX
				if result != NEWER || lsp.getUpdLifetime() == 0 {
					panic("Bad branch")
				}
			} else {
				// Create LSP and then force purge.
				lsp := db.newLSPSegment(payload, pdutype, tlvs)
				db.db[lspid] = lsp // XXX check if we can
				// consolidate or if we need to leave for acks
				db.initiatePurgeLSP(lsp)
				return
			}
		}
		// d) Ours, supported and wire is newer, need to increment our
		// copy per 7.3.16.1
		if !unsupported && result == NEWER {
			// If this is supported we better have a non-expired LSP in the DB.
			//assert dblsp
			//assert dblsp.lifetime
			//self._update_own_lsp(dblsp.pdubuf, dblsp.tlvs, frame.seqno)
			return
		}

	}

	// [ also: ISO 10589 17.3.16.4: a, b ]
	// e1) Newer - update db, flood and acknowledge
	//     [ also: ISO 10589 17.3.16.4: b.1 ]
	if result == NEWER {
		if lsp != nil && lsp.life != nil {
			if !lsp.life.Stop() {
				// This means the LSP segment just expired and we were
				// unable to stop the hold timer b/c we haven't
				// handled the event yet.  We need to recheck
				// NEWER now, it will either remain NEWER or
				// switch to SAME.
				result = compareLSP(lsp, newhdr)
			} else {
				// We've now stopped the timer we would have
				// reset it anyway in updateLSPSegment.

			}
		}
	}

	if result == NEWER {
		if lsp != nil {
			db.debug("Updating LSP from %s", c)
			db.updateLSPSegment(lsp, payload, pdutype, tlvs)
		} else {
			db.debug("Added LSP from %s", c)
			if nlifetime == 0 {
				// 17.3.16.4: a
				// XXX send ack on circuit do not retain
				return
			}
			lsp = db.newLSPSegment(payload, pdutype, tlvs)
			db.db[lspid] = lsp
		}

		db.setAllFlag(SRM, &lsp.lspid, c)
		db.clearFlag(SRM, &lsp.lspid, c)
		if c.IsP2P() {
			db.setFlag(SSN, &lsp.lspid, c)
		}
		db.clearAllFlag(SSN, &lsp.lspid, c)
	} else if result == SAME {
		// e2) Same - Stop sending and Acknowledge
		//     [ also: ISO 10589 17.3.16.4: b.2 ]
		db.clearAllFlag(SRM, &lsp.lspid, nil)
		if c.IsP2P() {
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

// updateLSP updates an lspSegment with a newer version received on a link.
func (db *DB) updateLSPSegment(lsp *lspSegment, payload []byte, pdutype clns.PDUType, tlvs map[tlv.Type][]tlv.Data) {
	if db.debug != nil {
		db.debug("Updating %s", lsp)
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
			db.debug("Received Purge LSP %s", lsp)
			lsp.zeroLife = xtime.NewHoldTimer(clns.ZeroMaxAge,
				func() { db.expireC <- lsp.lspid })
		} else if lsp.zeroLife.Until() < clns.ZeroMaxAge {
			// Refresh zero age. If we can't reset the timer b/c
			// it's firing just create a new one. We handle it.
			if !lsp.zeroLife.Reset(clns.ZeroMaxAge) {
				lsp.zeroLife = xtime.NewHoldTimer(clns.ZeroMaxAge,
					func() { db.expireC <- lsp.lspid })
			}
		}
		return
	}

	if lsp.life != nil {
		// Reset the hold timer
		lsp.life.Reset(lifetime)
	} else {
		// We should never see both nil we would have deleted it.
		if lsp.zeroLife == nil {
			panic(fmt.Sprintf("WARNING: both life and zero nil for %s", lsp))
		}
		// No need to check if we sotpped as we can handle being
		// called now after update.
		lsp.zeroLife.Stop()
		lsp.zeroLife = nil
		lsp.life = xtime.NewHoldTimer(lifetime, func() { db.expireC <- lsp.lspid })
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

	db.debug("Updated %s", lsp)
}

func (db *DB) runOnce() {
	select {
	case in := <-db.disC:
		if db.dis[in.cid] == BoolToTrit(in.set) {
			break
		}
		db.debug("UPD: DIS Change for %d to %d", in.cid, in.set)
		db.dis[in.cid] = BoolToTrit(in.set)
		// XXX Originate or Purge PNode.

	case in := <-db.lspC:
		db.receiveLSP(in.c, in.payload, in.pdutype, in.tlvs)

	// Do things above this that may affect expiration of LSP segment
	case lspid := <-db.expireC:
		db.debug("1) <-expireC %s", lspid)
		// Come in here 2 ways, either with zeroLifetime non-nil but
		// expired in which case we should be good to remove, or nil
		// b/c the hold timer fired for this LSP.
		lsp, ok := db.db[lspid]
		if !ok {
			// it's gone we're done.
			db.debug("Warning: <-expireC %s not present", lspid)
			break
		}
		db.debug("2) <-expireC %s", lspid)
		if lsp.life != nil && lsp.life.Until() != 0 {
			db.debug("<-expireC: %s ressurected", lsp)
			break
		}
		db.debug("3) <-expireC %s", lspid)
		if lsp.zeroLife == nil {
			db.debug("4) <-expireC %s", lspid)
			db.initiatePurgeLSP(lsp)
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
	case in := <-db.getsnpC:
		lsp, ok := db.db[*in.lspid]
		if !ok {
			in.result <- false
			break
		}
		lsp.getUpdLifetime()
		copy(in.ent, lsp.hdr[clns.HdrLSPLifetime:clns.HdrLSPFlags])
		in.result <- true

	case in := <-db.getlspC:
		lsp, ok := db.db[*in.lspid]
		if !ok {
			in.result <- 0
			break
		}
		lsp.getUpdLifetime()
		in.result <- copy(in.payload, lsp.payload)

	}
}

// Run runs the update process
func (db *DB) Run() {
	for {
		db.runOnce()
	}
}
