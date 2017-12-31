// Update implements the update process (flooding)
package main

import (
	"bytes"
	"fmt"
	"github.com/choppsv1/goisis/clns"
	"github.com/choppsv1/goisis/pkt"
	"sync"
	"time"
)

// =====
// Types
// =====

// FlagIndex Update process flooding flags (not true flags)
type FlagIndex int

// UpdateDB holds all LSP for a given level.
type UpdateDB struct {
	lindex clns.LIndex
	db     map[clns.LSPID]*LSPSegment

	// Any changes to LSP or the db map need to be done with this lock held.
	L sync.Mutex
}

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

// LSPSegment represents an LSP segment from an IS.
type LSPSegment struct {
	pdu          PDU
	hdr          []byte
	lspid        clns.LSPID
	lindex       clns.LIndex
	lifetime     *Holdtime
	zeroLifetime *Holdtime
	holdTimer    *time.Timer
	refreshTimer *time.Timer
	isAck        bool
	purgeLock    sync.Mutex
}

// CopyLSPPayload copies the LSP payload buffer for sending if found and returns
// the count of copied bytes, otherwise returns 0.
//
// XXX With different locking we may not need a copy.
func (db *UpdateDB) CopyLSPPayload(lspid *clns.LSPID, payload []byte) int {
	db.L.Lock()
	defer db.L.Unlock()

	l := 0
	if lsp, ok := db.db[*lspid]; ok {
		l = copy(payload, lsp.pdu.payload)
	}
	return l
}

// CopyLSPSNP copies the LSPSegment SNP data if found and return true, else false
func (db *UpdateDB) CopyLSPSNP(lspid *clns.LSPID, ent []byte) bool {
	db.L.Lock()
	defer db.L.Unlock()

	lsp, ok := db.db[*lspid]
	if ok {
		copy(ent, lsp.hdr[clns.HdrLSPLifetime:clns.HdrLSPFlags])
	}
	return ok
}

// removeLSPLocked removes and LSP from the update LSP DB with lock held
func (db *UpdateDB) removeLSPLocked(lsp *LSPSegment) {
	delete(db.db, lsp.lspid)
}

// StringLocked returns a string identifying the LSP DB lock must be held
func (lsp *LSPSegment) StringLocked() string {
	return fmt.Sprintf("LSP(id:%s seqno:%#08x lifetime:%v cksum:%#04x",
		clns.ISOString(lsp.getLSPIDLocked(), false),
		lsp.getSeqNoLocked(),
		lsp.getLifetimeLocked(),
		lsp.getCksumLocked())
}

// NewLSPSegment creates a new LSPSegment struct
func NewLSPSegment(pdu *PDU) (*LSPSegment, error) {
	hdr := pdu.payload[clns.HdrCLNSSize:]
	hdr = hdr[:clns.HdrLSPSize]
	lsp := &LSPSegment{
		pdu:    *pdu,
		hdr:    hdr,
		lindex: pdu.pdutype.GetPDULIndex(),
	}
	copy(lsp.lspid[:], hdr[clns.HdrLSPLSPID:])
	lifetime := pkt.GetUInt16(hdr[clns.HdrLSPLifetime:])
	lsp.lifetime = NewHoldtime(lifetime)
	lsp.holdTimer = time.AfterFunc(lsp.lifetime.TimeLeft(), lsp.expire)
	// We aren't locked but this isn't in the DB yet.
	if lsp.isOursLocked() {
		lsp.refreshTimer = time.NewTimer(lsp.lifetime.TimeLeft())
	}
	return lsp, nil
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

func (lsp *LSPSegment) isOursLocked() bool {
	return bytes.Equal(lsp.getLSPIDLocked()[:clns.SysIDLen], GlbSystemID)
}

// Update updates an LSPSegment with a newer version received on a link.
func (lsp *LSPSegment) Update(pdu *PDU) error {
	lsp.purgeLock.Lock()
	defer lsp.purgeLock.Unlock()
	GlbUpdateDB[lsp.lindex].L.Lock()
	defer GlbUpdateDB[lsp.lindex].L.Unlock()

	if debugIsSet(DbgFLSP) {
		s := lsp.StringLocked()
		debug(DbgFLSP, "Updating %s", s)
	}
	// XXX I think this is wrong... we need to understand this better.
	if !lsp.holdTimer.Stop() {
		// if timer wasn't active drain it.
		<-lsp.holdTimer.C
	}

	// oldpdu := lsp.pdu
	// oldhdr := lsp.hdr

	hdr := pdu.payload[clns.HdrCLNSSize:]
	hdr = hdr[:clns.HdrLSPSize]
	lsp.pdu = *pdu
	lsp.hdr = hdr
	lifetime := pkt.GetUInt16(hdr[clns.HdrLSPLifetime:])

	// This LSP is being purged
	if lifetime == 0 {
		if lsp.zeroLifetime == nil {
			lsp.zeroLifetime = NewHoldtime(clns.ZeroMaxAge)
		} else if lsp.zeroLifetime.TimeLeft() < clns.ZeroMaxAge {
			// this is due to a seqno Update
			lsp.zeroLifetime.Reset(clns.ZeroMaxAge)
		}
		lsp.holdTimer.Reset(lsp.zeroLifetime.TimeLeft())
		debug(DbgFLSP, "Updated zero-lifetime LSP to %s", lsp)
		return nil
	}

	// Reset the hold timer
	lsp.zeroLifetime = nil
	lsp.lifetime.Reset(lifetime)
	lsp.holdTimer.Reset(time.Duration(lifetime) * time.Second)

	if lsp.isOursLocked() {
		// assert(lsp.refreshTimer != nil)
		timeleft := (lifetime * 3) / 4
		// assert timeleft
		if !lsp.refreshTimer.Stop() {
			<-lsp.refreshTimer.C
		}
		lsp.refreshTimer.Reset(time.Duration(timeleft) * time.Second)
	}

	debug(DbgFLSP, "Updated %s", lsp)
	return nil
}

// expire is run on hold time expiration. This will occur either when the
// initial lifetime ends, or after zeroLifetime expires to remove the LSPSegment
// from the DB.
func (lsp *LSPSegment) expire() {
	lsp.purgeLock.Lock()
	defer lsp.purgeLock.Unlock()
	GlbUpdateDB[lsp.lindex].L.Lock()
	defer GlbUpdateDB[lsp.lindex].L.Unlock()

	lifetime := pkt.GetUInt16(lsp.hdr[clns.HdrLSPLifetime:])
	if lifetime != 0 {
		// Something updated the LSP so stop expiring it.
		return
	}

	if lsp.zeroLifetime != nil {
		// assert lsp.hdr.lifetime == 0
		lsp.zeroLifetime = nil
		debug(DbgFLSP, "Removing zero-lifetime LSP %s", lsp)
		GlbUpdateDB[lsp.lindex].removeLSPLocked(lsp)
		return
	}
	// // Debug
	// if lsp.getSeqNo() == 0 {
	// }

	pkt.PutUInt16(lsp.hdr[:clns.HdrLSPLifetime], 0)
	lsp.purgeExpiredLocked()
}

// purgeExpired purges the LSP, must be called with purge lock held
func (lsp *LSPSegment) purgeExpiredLocked() {
	// assert(self.purgeLock.Locked())

	//-----------------------------
	// ISO10589: 7.3.16.4: a, b, c
	//-----------------------------

	// a)
	GlbCDB.SetAllSRM(lsp)

	// b) Retain only LSP header. XXX we need more space for auth and purge tlv
	pdulen := uint16(clns.HdrCLNSSize + clns.HdrLSPSize)
	lsp.pdu.payload = lsp.pdu.payload[:pdulen]
	pkt.PutUInt16(lsp.hdr[clns.HdrLSPCksum:], 0)
	pkt.PutUInt16(lsp.hdr[clns.HdrLSPPDULen:], pdulen)

}
