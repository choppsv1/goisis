//
// -*- coding: utf-8 -*-
//
// December 12 2018, Christian E. Hopps <chopps@gmail.com>
//
//
package update

import (
	"github.com/choppsv1/goisis/clns"
	"github.com/choppsv1/goisis/pkt"
	"github.com/choppsv1/goisis/tlv"
	"time"
)

type Segment struct {
	payload  []byte
	refreshT time.Timer
}

type LSP struct {
	Pnid      uint8
	li        clns.LIndex
	l         clns.Level
	db        *DB
	c         Circuit
	segments  map[uint8][]byte
	regenWait *time.Timer
}

// NewLSP creates a new LSP for the router.
func NewLSP(pnid byte, db *DB, c Circuit) *LSP {
	lsp := &LSP{
		Pnid:     pnid,
		li:       db.li,
		db:       db,
		c:        c,
		segments: make(map[uint8][]byte),
	}

	// Just use this code when we need nodeid
	// copy(lsp.Nodeid[:], GlbSystemID[:])
	// nodeid[clns.SysIDLen] = pnid

	// We delay generating non-pnode a short time to gather startup changes.
	delay := LSPGenDelay
	if pnid == 0 {
		// We only long delay for our own (non-pnode) LSP.
		delay = LSPCreateGenDelay
	}
	lsp.regenWait = time.AfterFunc(delay,
		func() { db.chgLSPC <- chgLSP{timer: true, pnid: pnid} })

	lsp.db.debug("%s: LSP pnid %d generation scheduled %s", lsp.li, pnid, delay)

	return lsp
}

// finishSegment update the LSP segment header prior to pushing out.
// send previous buffer to the update process.
func (lsp *LSP) finishSegment(payload []byte, i uint) error {
	clns.InitHeader(payload, clns.LSPTypeMap[lsp.db.li])
	hdr := Slicer(payload, clns.HdrCLNSSize, clns.HdrLSPSize)
	lspbuf := payload[clns.HdrCLNSSize:]

	// Increment seqno
	seqno := uint32(0)
	lspid := clns.MakeLSPID(lsp.db.sysid, lsp.Pnid, uint8(i))
	dblsp := lsp.db.db[lspid]
	if dblsp != nil {
		seqno = dblsp.getSeqNo()
	}
	seqno += 1 // XXX check for rollover.

	// Fill in LSP header
	pkt.PutUInt16(hdr[clns.HdrLSPPDULen:], uint16(len(payload)))
	pkt.PutUInt16(hdr[clns.HdrLSPLifetime:], clns.MaxAge)
	copy(hdr[clns.HdrLSPLSPID:], lspid[:])
	pkt.PutUInt32(hdr[clns.HdrLSPSeqNo:], seqno)
	pkt.PutUInt16(hdr[clns.HdrLSPCksum:], 0)
	hdr[clns.HdrLSPFlags] = clns.MakeLSPFlags(0, lsp.db.istype)
	cksum := clns.Cksum(lspbuf[clns.HdrLSPLSPID:], 13)
	pkt.PutUInt16(hdr[clns.HdrLSPCksum:], cksum)

	// Input into our DB.
	tlvs, err := tlv.Data(hdr[clns.HdrLSPSize:]).ParseTLV()
	if err != nil {
		panic("Invalid TLV from ourselves")
	}
	lsp.db.receiveLSP(nil, payload, tlvs)

	return nil
}

// regenerate non-pnode LSP
func (lsp *LSP) regenNonPNodeLSP() error {
	lsp.db.debug("%s: Non-PN LSP Generation starts", lsp.li)

	bt := tlv.NewBufferTrack(clns.LSPOrigBufSize, clns.HdrCLNSSize+clns.HdrLSPSize, 256,
		func(buf tlv.Data, i uint) error {
			return lsp.finishSegment(buf, i)
		})

	if lsp.li.ToLevel() == 2 {
		if err := bt.AddAreas(lsp.db.areas); err != nil {
			lsp.db.debug("Error adding area TLV: %s", err)
			return err
		}
	}
	if err := bt.AddNLPID(lsp.db.nlpid); err != nil {
		lsp.db.debug("Error adding NLPID TLV: %s", err)
		return err
	}

	// Add Hostname, ignore error.
	if err := bt.AddHostname(lsp.db.hostname); err != nil {
		// XXX warning instead of debug?
		lsp.db.debug("Error adding Hostname TLV: %s", err)
	}

	if err := bt.AddIntfAddrs(lsp.db.Addrs(true)); err != nil {
		return err
	}

	if err := bt.AddIntfAddrs(lsp.db.Addrs(false)); err != nil {
		return err
	}

	// IS Reach (don't use)

	// Ext Reach

	// Prefixes

	// External Gen App

	return bt.Close()

}

// regenerate pnode LSP
func (lsp *LSP) regenPNodeLSP() error {
	lsp.db.debug("%s: PN LSP Generation starts", lsp.li)

	// Ext Reach
	return nil
	// return bt.Close()
}

// regenLSP regenerates the LSP.
func (lsp *LSP) regenLSP() error {
	if lsp.Pnid > 0 {
		return lsp.regenPNodeLSP()
	} else {
		return lsp.regenNonPNodeLSP()
	}
}
