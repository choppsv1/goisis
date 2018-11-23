// Package update implements the update process (flooding)
package update

import (
	"bytes"
	"fmt"
	"github.com/choppsv1/goisis/clns"
	"github.com/choppsv1/goisis/pkt"
	xtime "github.com/choppsv1/goisis/time"
	"github.com/choppsv1/goisis/tlv"
	"time"
)

// =====
// Types
// =====

// Circuit interface used by the Update Process
type CircuitDB interface {
	IsDIS(li clns.LIndex, pnid uint8) bool
	GetFlagsC() chan<- ChgSxxFlag
}

type Circuit interface {
	ClearFlag(flag SxxFlag, lspid *clns.LSPID, li clns.LIndex)
	SetFlag(flag SxxFlag, lspid *clns.LSPID, li clns.LIndex)
}

// DB holds all LSP for a given level.
type DB struct {
	sysid   clns.SystemID
	lspC    chan inputPDU
	cdb     CircuitDB
	flagsC  chan<- ChgSxxFlag
	getlspC chan inputGetLSP
	getsnpC chan inputGetSNP
	expireC chan clns.LSPID
	li      clns.LIndex
	db      map[clns.LSPID]*lspSegment
	debug   func(string, ...interface{})
}

// ErrIIH is a general error in IIH packet processing
type ErrLSP string

func (e ErrLSP) Error() string {
	return fmt.Sprintf("ErrLSP: %s", string(e))
}

// inputPDU is the PDU input to the udpate process
type inputPDU struct {
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
	payload      []byte
	hdr          []byte
	tlvs         map[tlv.Type][]tlv.Data
	lspid        clns.LSPID
	li           clns.LIndex
	lifetime     *xtime.Timeout
	zeroLifetime *xtime.Timeout
	holdTimer    *time.Timer
	isAck        bool
	isOurs       bool
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
func NewDB(sysid []byte, l clns.Level, cdb CircuitDB, debug func(string, ...interface{})) *DB {
	fmt.Printf("UPD: debug: %p", debug)
	db := &DB{
		debug:   debug,
		li:      l.ToIndex(),
		cdb:     cdb,
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

	db.lspC <- inputPDU{payload, pdutype, tlvs}
	return nil
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
// Internal Functionality only called in the update go routine, no locking required.
//

// String returns a string identifying the LSP DB lock must be held
func (lsp *lspSegment) String() string {
	s := clns.ISOString(lsp.getLSPID(), false)
	return fmt.Sprintf("LSP(id:%s seqno:%#08x lifetime:%v cksum:%#04x",
		s,
		lsp.getSeqNo(),
		lsp.getLifetime(),
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

	lifesec := int(pkt.GetUInt16(hdr[clns.HdrLSPLifetime:]))
	lsp.lifetime = xtime.NewTimeoutSec(lifesec)
	lsp.holdTimer = time.AfterFunc(lsp.lifetime.Remaining(),
		func() { db.expireC <- lsp.lspid })

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

func (lsp *lspSegment) getLifetime() uint16 {
	return pkt.GetUInt16(lsp.hdr[clns.HdrLSPLifetime:])
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
	olifetime := lsp.getLifetime()
	if nlifetime == 0 && olifetime != 0 {
		return NEWER
	} else if olifetime == 0 && nlifetime != 0 {
		return OLDER
	}
	return SAME
}

// recvPurgeLSP handles a received lifetime == 0 LSPSegment
func (db *DB) recvPurgeLSP(lsp *lspSegment) {
	if lsp.zeroLifetime == nil {
		lsp.zeroLifetime = xtime.NewTimeout(clns.ZeroMaxAgeDur)
	} else if lsp.zeroLifetime.Remaining() < clns.ZeroMaxAgeDur {
		// this is due to a seqno Update
		lsp.zeroLifetime.Reset(clns.ZeroMaxAgeDur)
	}
	lsp.holdTimer.Reset(lsp.zeroLifetime.Remaining())
	if db.debug != nil {
		db.debug("Updated zero-lifetime LSP %s to %s", lsp, lsp.holdTimer)
	}
}

// initiatePurgeLSP initiates a purge of an LSPSegment due to lifetime running
// to zero.
func (db *DB) initiatePurgeLSP(lsp *lspSegment) {
	// Update the lifetime to zero if it wasn't already.
	pkt.PutUInt16(lsp.hdr[:clns.HdrLSPLifetime], 0)

	if db.debug != nil {
		db.debug("Lifetime for %s expired, purging.", lsp)
	}

	lsp.zeroLifetime = xtime.NewTimeout(clns.ZeroMaxAgeDur)
	wasActive := lsp.holdTimer.Reset(lsp.zeroLifetime.Remaining())
	if wasActive {
		db.debug("XXX hold timer was active when it should not have been")
	}

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

func (db *DB) updateLSPLifetime(lsp *lspSegment) {
	// Update the lifetime value of this LSP possibly initiating a purge
	if lsp.getLifetime() > 0 {
		lifetime := lsp.lifetime.RemainingSec()
		lsp.setLifetime(uint16(lifetime))
		if lifetime == 0 {
			// We've noticed lifetime going to zero prior
			// our timer firing, purge it now.

			// Stop our timer now as we are going to purge.
			if !lsp.holdTimer.Stop() {
				// if timer wasn't active drain it.
				<-lsp.holdTimer.C
			}
			db.initiatePurgeLSP(lsp)
		}
	} else {
		// lifetime already zero we have to be purging still
		if lsp.zeroLifetime == nil {
			panic("zeroLifetime not set on expired LSP")
		}
	}
}

// receiveLSP receives an LSP from flooding
func (db *DB) receiveLSP(payload []byte, pdutype clns.PDUType, tlvs map[tlv.Type][]tlv.Data) {
	var lspid clns.LSPID
	copy(lspid[:], payload[clns.HdrCLNSSize+clns.HdrLSPLSPID:])

	lsp := db.db[lspid]
	llifetime := lsp.getLifetime()

	newhdr := Slicer(payload, clns.HdrCLNSSize, clns.HdrLSPSize)
	nlifetime := pkt.GetUInt16(newhdr[clns.HdrLSPLifetime:])

	result := compareLSP(lsp, newhdr)
	isOurs := bytes.Equal(lspid[:clns.SysIDLen], db.sysid[:])

	if isOurs {
		pnid := lsp.lspid[7]
		var unsupported bool
		if pnid == 0 {
			unsupported = false // always support non-pnode LSP
		} else {
			unsupported = lsp == nil || db.cdb.IsDIS(db.li, pnid)
		}
		// b) If the LSP has zero Remaining Lifetime, perform the
		//    actions described in 7.3.16.4. -- for LSPs not ours this
		//    is the same as normal handling except that we do not add a
		//    missing LSP segment, instead we acknowledge receipt only.
		if unsupported && nlifetime != 0 {
			if lsp != nil {
				if result != NEWER || llifetime == 0 {
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
		// d) Ours, supported and wire is newer, need to increment our copy per 7.3.16.1
		if !unsupported && result == NEWER {
			// If this is supported we better have a non-expired LSP in the DB.
			//assert dblsp
			//assert dblsp.lifetime
			//self._update_own_lsp(dblsp.pdubuf, dblsp.tlvs, frame.seqno)
			return
		}

	}
}

// updateLSP updates an lspSegment with a newer version received on a link.
func (db *DB) updateLSP(lsp *lspSegment, payload []byte, pdutype clns.PDUType, tlvs map[tlv.Type][]tlv.Data) {
	if db.debug != nil {
		db.debug("Updating %s", lsp)
	}

	newhdr := Slicer(payload, clns.HdrCLNSSize, clns.HdrLSPSize)
	compareLSP(lsp, newhdr)

	// // XXX I think this is wrong... we need to understand this better.
	// if !lsp.holdTimer.Stop() {
	// 	// if timer wasn't active drain it.
	// 	<-lsp.holdTimer.C
	// }

	// if lsp.isOurs {
	// 	pnid := lsp.lspid[7]
	// }

	// We are replacing the previous PDU payload slice thus we are
	// relinquishing our reference on that previous PDU frame
	lsp.payload = payload
	lsp.hdr = Slicer(payload, clns.HdrCLNSSize, clns.HdrLSPSize)
	lifetime := time.Duration(pkt.GetUInt16(lsp.hdr[clns.HdrLSPLifetime:])) * time.Second

	// This LSP is now being purged
	if lifetime == 0 {
		db.recvPurgeLSP(lsp)
		return
	}

	// Reset the hold timer
	lsp.zeroLifetime = nil
	lsp.lifetime.Reset(lifetime)
	lsp.holdTimer.Reset(lifetime)

	// if lsp.isOurs {
	// 	// assert(lsp.refreshTimer != nil)
	// 	timeleft := lifetime * 3 / 4
	// 	// assert timeleft
	// 	if !lsp.refreshTimer.Stop() {
	// 		<-lsp.refreshTimer.C
	// 	}
	// 	lsp.refreshTimer.Reset(timeleft)
	// }

	if db.debug != nil {
		db.debug("Updated %s", lsp)
	}
}

func (db *DB) runOnce() {
	select {
	case in := <-db.lspC:
		var lspid clns.LSPID
		copy(lspid[:], in.payload[clns.HdrCLNSSize+clns.HdrLSPLSPID:])
		lsp, ok := db.db[lspid]
		if ok {
			db.updateLSP(lsp, in.payload, in.pdutype, in.tlvs)
		} else {
			lsp := db.newLSPSegment(in.payload, in.pdutype, in.tlvs)
			db.db[lspid] = lsp
		}

	case in := <-db.getsnpC:
		lsp, ok := db.db[*in.lspid]
		if !ok {
			in.result <- false
			break
		}
		db.updateLSPLifetime(lsp)
		copy(in.ent, lsp.hdr[clns.HdrLSPLifetime:clns.HdrLSPFlags])
		in.result <- true

	case in := <-db.getlspC:
		lsp, ok := db.db[*in.lspid]
		if !ok {
			in.result <- 0
			break
		}
		db.updateLSPLifetime(lsp)
		in.result <- copy(in.payload, lsp.payload)

	case lspid := <-db.expireC:
		// Come in here 2 ways, either with zeroLifetime non-nil but
		// expired in which case we should be good to remove, or nil
		// b/c the hold timer fired for this LSP.
		lsp, ok := db.db[lspid]
		if !ok {
			// it's gone we're done.
			db.debug("Warning: <-expireC %s not present", lspid)
			break
		}
		if !lsp.lifetime.IsExpired() {
			// Must have updated the LSP to not be expired.
			db.debug("<-expireC: %s ressurected", lspid)
			break
		}
		if lsp.zeroLifetime != nil {
			if !lsp.zeroLifetime.IsExpired() {
				panic("expiring non-zero lifetime expired LSP")
			}
			lsp.zeroLifetime = nil
			if db.debug != nil {
				db.debug("Removing zero-lifetime LSP %s", lsp)
			}
			delete(db.db, lsp.lspid)
			break
		}

		db.initiatePurgeLSP(lsp)
	}
}

// Run runs the update process
func (db *DB) Run() {
	for {
		db.runOnce()
	}
}
