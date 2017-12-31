// Update implements the update process (flooding)
package update

import (
	"fmt"
	"github.com/choppsv1/goisis/clns"
	"github.com/choppsv1/goisis/pkt"
	xtime "github.com/choppsv1/goisis/time"
	"github.com/choppsv1/goisis/tlv"
	"sync"
	"time"
)

// =====
// Types
// =====

// Input is the PDU input to the udpate process

type Input struct {
	payload []byte
	pdutype clns.PDUType
	tlvs    map[tlv.Type][]tlv.Data
}

// InputGetLSP is the input to db.GetLSP channel
type InputGetLSP struct {
	lspid   *clns.LSPID
	payload []byte
	result  chan int
}

// InputGetSNP is the input to db.GetSNP channel
type InputGetSNP struct {
	lspid  *clns.LSPID
	ent    []byte
	result chan bool
}

// UpdateDB holds all LSP for a given level.
type UpdateDB struct {
	Input     chan Input
	GetLSP    chan InputGetLSP
	GetSNP    chan InputGetSNP
	expireLSP chan clns.LSPID
	lindex    clns.LIndex
	db        map[clns.LSPID]*LSPSegment
	setsrm    func(*clns.LSPID)
	debug     func(string, ...interface{})
}

// LSPSegment represents an LSP segment from an IS.
type LSPSegment struct {
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

// NewUpdateDB returns a new Update Process LSP database
func NewUpdateDB(lindex clns.LIndex,
	setsrm func(*clns.LSPID),
	debug func(string, ...interface{})) *UpdateDB {
	db := &UpdateDB{
		lindex:    lindex,
		db:        make(map[clns.LSPID]*LSPSegment),
		setsrm:    setsrm,
		Input:     make(chan Input),
		GetLSP:    make(chan InputGetLSP),
		GetSNP:    make(chan InputGetSNP),
		expireLSP: make(chan clns.LSPID),
	}
	return db
}

// CopyLSPPayload copies the LSP payload buffer for sending if found and returns
// the count of copied bytes, otherwise returns 0.
//
func (db *UpdateDB) CopyLSPPayload(lspid *clns.LSPID, payload []byte) int {
	result := make(chan int)
	db.GetLSP <- InputGetLSP{lspid, payload, result}
	l := <-result
	return l
}

// CopyLSPSNP copies the LSPSegment SNP data if found and return true, else false
func (db *UpdateDB) CopyLSPSNP(lspid *clns.LSPID, ent []byte) bool {
	result := make(chan bool)
	db.GetSNP <- InputGetSNP{lspid, ent, result}
	found := <-result
	return found
}

// StringLocked returns a string identifying the LSP DB lock must be held
func (lsp *LSPSegment) StringLocked() string {
	return fmt.Sprintf("LSP(id:%s seqno:%#08x lifetime:%v cksum:%#04x",
		clns.ISOString(lsp.getLSPIDLocked(), false),
		lsp.getSeqNoLocked(),
		lsp.getLifetimeLocked(),
		lsp.getCksumLocked())
}

// newLSPSegment creates a new LSPSegment struct
func (db *UpdateDB) newLSPSegment(payload []byte, pdutype clns.PDUType, tlvs map[tlv.Type][]tlv.Data) *LSPSegment {
	hdr := payload[clns.HdrCLNSSize:]
	hdr = hdr[:clns.HdrLSPSize]
	lsp := &LSPSegment{
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

	// // We aren't locked but this isn't in the DB yet.
	// if lsp.isOursLocked() {
	//      lsp.refreshTimer = time.NewTimer(lsp.lifetime.Remainingg())
	// }
	return lsp
}

func (lsp *LSPSegment) getSeqNoLocked() uint32 {
	return pkt.GetUInt32(lsp.hdr[clns.HdrLSPSeqNo:])
}

func (lsp *LSPSegment) getLifetimeLocked() uint16 {
	return pkt.GetUInt16(lsp.hdr[clns.HdrLSPLifetime:])
}

func (lsp *LSPSegment) getCksumLocked() uint16 {
	return pkt.GetUInt16(lsp.hdr[clns.HdrLSPCksum:])
}

// func (lsp *LSPSegment) getFlags() clns.LSPFlags {
// 	return clns.LSPFlags(lsp.hdr[clns.HdrLSPFlags])
// }

func (lsp *LSPSegment) getLSPIDLocked() []byte {
	return lsp.hdr[clns.HdrLSPLSPID : clns.HdrLSPLSPID+clns.LSPIDLen]
}

// func (lsp *LSPSegment) isOursLocked() bool {
// 	return bytes.Equal(lsp.getLSPIDLocked()[:clns.SysIDLen], GlbSystemID)
// }

// updateLSP updates an LSPSegment with a newer version received on a link.
func (db *UpdateDB) updateLSP(lsp *LSPSegment, payload []byte, pdutype clns.PDUType, tlvs map[tlv.Type][]tlv.Data) {
	if db.debug != nil {
		s := lsp.StringLocked()
		db.debug("Updating %s", s)
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
		return
	}

	// Reset the hold timer
	lsp.zeroLifetime = nil
	lsp.lifetime.Reset(lifetime)
	lsp.holdTimer.Reset(lifetime)

	// if lsp.isOursLocked() {
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

func (db *UpdateDB) runOnce() {
	select {
	case in := <-db.Input:
		var lspid clns.LSPID
		copy(lspid[:], in.payload[clns.HdrCLNSSize+clns.HdrLSPLSPID:])
		lsp, ok := db.db[lspid]
		if ok {
			db.updateLSP(lsp, in.payload, in.pdutype, in.tlvs)
		} else {
			lsp := db.newLSPSegment(in.payload, in.pdutype, in.tlvs)
		}
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
			// Must have updated
			break
		}
		if lsp.zeroLifetime != nil {
			lsp.zeroLifetime = nil
			if db.debug != nil {
				db.debug("Removing zero-lifetime LSP %s", lsp)
			}
			delete(db.db, lsp.lspid)
			break
		}

		//
		// Our hold timer expired b/c this LSP was not refreshed.
		//

		// Update the lifetime to zero if it wasn't already.
		pkt.PutUInt16(lsp.hdr[:clns.HdrLSPLifetime], 0)

		if db.debug != nil {
			db.debug("Lifetime for %s expired, purging.", lsp.StringLocked())
		}

		lsp.zeroLifetime = xtime.NewTimeout(clns.ZeroMaxAgeDur)
		wasActive := lsp.holdTimer.Reset(lsp.zeroLifetime.Remaining())

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
	case in := <-db.GetSNP:
		lsp, ok := db.db[*in.lspid]
		if ok {
			copy(in.ent, lsp.hdr[clns.HdrLSPLifetime:clns.HdrLSPFlags])
		}
		in.result <- ok
	case in := <-db.GetLSP:
		if lsp, ok := db.db[*in.lspid]; !ok {
			in.result <- 0
		} else {
			in.result <- copy(in.payload, lsp.payload)
		}
	}
}

// Run runs the update process
func (db *UpdateDB) Run() {
	for {
		db.runOnce()
	}
}
