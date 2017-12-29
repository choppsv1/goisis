package main

import (
	"bytes"
	"fmt"
	"github.com/choppsv1/goisis/clns"
	"github.com/choppsv1/goisis/pkt"
	"sync"
	"time"
)

// LSPSegment represents an LSP segment from an IS.
type LSPSegment struct {
	pdu          PDU
	hdr          []byte
	lifetime     *Holdtime
	zeroLifetime *Holdtime
	holdTimer    *time.Timer
	refreshTimer *time.Timer
	isAck        bool
	purgeLock    sync.Mutex
}

func (lsp *LSPSegment) String() string {
	return fmt.Sprintf("LSP(id:%s seqno:%#08x lifetime:%v cksum:%#04x",
		clns.ISOString(lsp.getLSPID(), false),
		lsp.getSeqNo(),
		lsp.getLifetime(),
		lsp.getCksum())
}

// NewLSPSegment creates a new LSPSegment struct
func NewLSPSegment(pdu *PDU) (*LSPSegment, error) {
	hdr := pdu.payload[clns.HdrCLNSSize:]
	hdr = hdr[:clns.HdrLSPSize]
	lsp := &LSPSegment{
		pdu: *pdu,
		hdr: hdr,
	}
	lifetime := pkt.GetUInt16(hdr[clns.HdrLSPLifetime:])
	lsp.lifetime = NewHoldtime(lifetime)
	lsp.holdTimer = time.AfterFunc(lsp.lifetime.TimeLeft(), lsp.expireLSP)
	if lsp.isOurs() {
		lsp.refreshTimer = time.NewTimer(lsp.lifetime.TimeLeft())
	}
	return lsp, nil
}

func (lsp *LSPSegment) getSeqNo() uint32 {
	return pkt.GetUInt32(lsp.hdr[clns.HdrLSPSeqNo:])
}

func (lsp *LSPSegment) getLifetime() uint16 {
	return pkt.GetUInt16(lsp.hdr[clns.HdrLSPLifetime:])
}

func (lsp *LSPSegment) getLSPID() []byte {
	return lsp.hdr[clns.HdrLSPLSPID : clns.HdrLSPLSPID+clns.LSPIDLen]
}

func (lsp *LSPSegment) getCksum() uint16 {
	return pkt.GetUInt16(lsp.hdr[clns.HdrLSPCksum:])
}

func (lsp *LSPSegment) getFlags() clns.LSPFlags {
	return clns.LSPFlags(lsp.hdr[clns.HdrLSPFlags])
}

func (lsp *LSPSegment) isOurs() bool {
	return bytes.Equal(lsp.getLSPID()[:clns.SysIDLen], GlbSystemID)
}

func (lsp *LSPSegment) update(pdu *PDU) error {
	lsp.purgeLock.Lock()
	defer lsp.purgeLock.Unlock()

	debug(DbgFLSP, "Updating s", lsp)

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
			// this is due to a seqno update
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

	if lsp.isOurs() {
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

// purgeExpired purge the LSP, must be called with purge lock held
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

func (lsp *LSPSegment) expireLSP() {
	lsp.purgeLock.Lock()
	defer lsp.purgeLock.Unlock()

	if lsp.zeroLifetime != nil {
		// assert lsp.hdr.lifetime == 0
		lsp.zeroLifetime = nil
		debug(DbgFLSP, "Removing zero-lifetime LSP %s", lsp)
		updRemoveLSP(lsp)
		return
	}
	// // Debug
	// if lsp.getSeqNo() == 0 {
	// }

	pkt.PutUInt16(lsp.hdr[:clns.HdrLSPLifetime], 0)
	lsp.purgeExpiredLocked()
}
