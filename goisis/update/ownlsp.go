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
func (lsp *LSP) finishSegment(payload []byte, i uint8) error {
	lsp.segments[i] = payload

	clns.InitHeader(payload, clns.LSPTypeMap[lsp.db.li])
	hdr := Slicer(payload, clns.HdrCLNSSize, clns.HdrLSPSize)

	lspid := clns.MakeLSPID(lsp.db.sysid, lsp.Pnid, i)
	dblsp := lsp.db.db[lspid]

	seqno := uint32(0)
	if dblsp != nil {
		seqno = dblsp.getSeqNo()
	}

	// Fill in LSP header
	pkt.PutUInt16(hdr[clns.HdrLSPPDULen:], uint16(len(payload)))
	copy(hdr[clns.HdrLSPLSPID:], lspid[:])
	hdr[clns.HdrLSPFlags] = clns.MakeLSPFlags(0, lsp.db.istype)

	lsp.db.incSeqNo(payload, seqno)

	return nil
}

func (db *DB) purgeOwn(pnid, segid uint8) {
	db.debug("%s: Purge own segment: %x-%x", db, pnid, segid)

	lspid := clns.MakeLSPID(db.sysid, pnid, segid)
	lsp := db.db[lspid]
	if lsp == nil {
		return
	}

	db.initiatePurgeLSP(lsp, false)
}

// regenerate non-pnode LSP
func (lsp *LSP) regenNonPNodeLSP() error {
	lsp.db.debug("%s: Non-PN LSP Generation starts", lsp.li)

	oldseg := lsp.segments
	lsp.segments = make(map[uint8][]byte)

	bt := tlv.NewBufferTrack(clns.LSPOrigBufSize, clns.HdrCLNSSize+clns.HdrLSPSize, 256,
		func(buf tlv.Data, i uint8) error {
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

	if err := bt.Close(); err != nil {
		return err
	}

	// Now purge any unsupported segments.
	lsp.db.debug("%s: Purge own unsupported segments", lsp.li)
	for segid, _ := range oldseg {
		_, present := lsp.segments[segid]
		if !present {
			lsp.db.purgeOwn(0, segid)
		}
	}
	return nil
}

// regenerate pnode LSP
func (lsp *LSP) regenPNodeLSP() error {
	lsp.db.debug("%s: PN LSP Generation starts", lsp.li)

	// Ext Reach

	return nil

	// return bt.Close()

	// // Now purge any unsupported segments.
	// lsp.db.debug("%s: Purge own unsupported segments", lsp.li)
	// for segid, _ := range oldseg {
	// 	_, present := lsp.segments[segid]
	// 	if !present {
	// 		purgeOwn(pnid, segid)
	// 		// purge
	// 	}
	// }
}

// regenLSP regenerates the LSP.
func (lsp *LSP) regenLSP() error {
	if lsp.Pnid > 0 {
		return lsp.regenPNodeLSP()
	} else {
		return lsp.regenNonPNodeLSP()
	}
}
