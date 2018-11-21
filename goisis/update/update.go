// Package update implements the update process (flooding)
package update

import (
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

// inputPDU is the PDU input to the udpate process
type inputPDU struct {
	payload []byte
	pdutype clns.PDUType
	tlvs    map[tlv.Type][]tlv.Data
}

// inputGetLSP is the input to db.cgetlsp channel
type inputGetLSP struct {
	lspid   *clns.LSPID
	payload []byte
	result  chan int
}

// inputGetSNP is the input to db.cgetsnp channel
type inputGetSNP struct {
	lspid  *clns.LSPID
	ent    []byte
	result chan bool
}

// DB holds all LSP for a given level.
type DB struct {
	lspC      chan inputPDU
	cgetlsp   chan inputGetLSP
	cgetsnp   chan inputGetSNP
	expireLSP chan clns.LSPID
	lindex    clns.LIndex
	db        map[clns.LSPID]*lspSegment
	setsrm    func(*clns.LSPID)
	debug     func(string, ...interface{})
}

// lspSegment represents an LSP segment from an IS.
type lspSegment struct {
	payload      []byte
	hdr          []byte
	tlvs         map[tlv.Type][]tlv.Data
	lspid        clns.LSPID
	lindex       clns.LIndex
	lifetime     *xtime.Timeout
	zeroLifetime *xtime.Timeout
	holdTimer    *time.Timer
	isAck        bool
}

// NewDB returns a new Update Process LSP database
func NewDB(lindex clns.LIndex,
	setsrm func(*clns.LSPID),
	debug func(string, ...interface{})) *DB {
	fmt.Printf("UPD: debug: %q", debug)
	db := &DB{
		debug:     debug,
		lindex:    lindex,
		db:        make(map[clns.LSPID]*lspSegment),
		setsrm:    setsrm,
		lspC:      make(chan inputPDU),
		cgetlsp:   make(chan inputGetLSP),
		cgetsnp:   make(chan inputGetSNP),
		expireLSP: make(chan clns.LSPID),
	}
	return db
}

//
// External API no locking required.
//

// InputPDU creates or updates an LSP in the update DB.
func (db *DB) InputLSP(payload []byte, pdutype clns.PDUType, tlvs map[tlv.Type][]tlv.Data) {
	db.lspC <- inputPDU{payload, pdutype, tlvs}
}

// CopyLSPPayload copies the LSP payload buffer for sending if found and returns
// the count of copied bytes, otherwise returns 0.
func (db *DB) CopyLSPPayload(lspid *clns.LSPID, payload []byte) int {
	result := make(chan int)
	db.cgetlsp <- inputGetLSP{lspid, payload, result}
	l := <-result
	close(result)
	return l
}

// CopyLSPSNP copies the lspSegment SNP data if found and return true, else false
func (db *DB) CopyLSPSNP(lspid *clns.LSPID, ent []byte) bool {
	result := make(chan bool)
	db.cgetsnp <- inputGetSNP{lspid, ent, result}
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

// newLSPSegment creates a new lspSegment struct
func (db *DB) newLSPSegment(payload []byte, pdutype clns.PDUType, tlvs map[tlv.Type][]tlv.Data) *lspSegment {
	hdr := payload[clns.HdrCLNSSize:]
	hdr = hdr[:clns.HdrLSPSize]
	lsp := &lspSegment{
		payload: payload,
		hdr:     hdr,
		lindex:  pdutype.GetPDULIndex(),
		tlvs:    tlvs,
	}
	copy(lsp.lspid[:], hdr[clns.HdrLSPLSPID:])
	lifesec := int(pkt.GetUInt16(hdr[clns.HdrLSPLifetime:]))
	lsp.lifetime = xtime.NewTimeoutSec(lifesec)
	lsp.holdTimer = time.AfterFunc(lsp.lifetime.Remaining(),
		func() { db.expireLSP <- lsp.lspid })

	db.debug("New LSP")
	db.debug("New LSP: %s", lsp)
	// // We aren't locked but this isn't in the DB yet.
	// if lsp.isOurs() {
	//      lsp.refreshTimer = time.NewTimer(lsp.lifetime.Remainingg())
	// }
	return lsp
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

// func (lsp *lspSegment) isOurs() bool {
// 	return bytes.Equal(lsp.getLSPID()[:clns.SysIDLen], GlbSystemID)
// }

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
	db.setsrm(&lsp.lspid)

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

// updateLSP updates an lspSegment with a newer version received on a link.
func (db *DB) updateLSP(lsp *lspSegment, payload []byte, pdutype clns.PDUType, tlvs map[tlv.Type][]tlv.Data) {
	if db.debug != nil {
		db.debug("Updating %s", lsp)
	}
	// XXX I think this is wrong... we need to understand this better.
	if !lsp.holdTimer.Stop() {
		// if timer wasn't active drain it.
		<-lsp.holdTimer.C
	}

	// We are replacing the previous PDU payload slice thus we are
	// relinquishing our reference on that previous PDU frame
	hdr := payload[clns.HdrCLNSSize:]
	hdr = hdr[:clns.HdrLSPSize]
	lsp.payload = payload
	lsp.hdr = hdr
	lifetime := time.Duration(pkt.GetUInt16(hdr[clns.HdrLSPLifetime:])) * time.Second

	// This LSP is now being purged
	if lifetime == 0 {
		db.recvPurgeLSP(lsp)
		return
	}

	// Reset the hold timer
	lsp.zeroLifetime = nil
	lsp.lifetime.Reset(lifetime)
	lsp.holdTimer.Reset(lifetime)

	// if lsp.isOurs() {
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

	case in := <-db.cgetsnp:
		lsp, ok := db.db[*in.lspid]
		if !ok {
			in.result <- false
			break
		}
		db.updateLSPLifetime(lsp)
		copy(in.ent, lsp.hdr[clns.HdrLSPLifetime:clns.HdrLSPFlags])
		in.result <- true

	case in := <-db.cgetlsp:
		lsp, ok := db.db[*in.lspid]
		if !ok {
			in.result <- 0
			break
		}
		db.updateLSPLifetime(lsp)
		in.result <- copy(in.payload, lsp.payload)

	case lspid := <-db.expireLSP:
		// Come in here 2 ways, either with zeroLifetime non-nil but
		// expired in which case we should be good to remove, or nil
		// b/c the hold timer fired for this LSP.
		lsp, ok := db.db[lspid]
		if !ok {
			// it's gone we're done.
			break
		}
		if !lsp.lifetime.IsExpired() {
			// Must have updated the LSP to not be expired.
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
