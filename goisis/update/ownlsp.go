//
// -*- coding: utf-8 -*-
//
// December 12 2018, Christian E. Hopps <chopps@gmail.com>
//
//
package update

import (
	"github.com/choppsv1/goisis/clns"
	. "github.com/choppsv1/goisis/logging" // nolint
	"github.com/choppsv1/goisis/pkt"
	"github.com/choppsv1/goisis/tlv"
	"time"
)

type ownLSP struct {
	Pnid      uint8
	li        clns.LIndex
	db        *DB
	c         Circuit
	segments  map[uint8][]byte
	regenWait *time.Timer
}

// NewOwnLSP creates a new OwnLSP for the router.
func newOwnLSP(pnid byte, db *DB, c Circuit) *ownLSP {
	lsp := &ownLSP{
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
		// We only long delay for our own (non-pnode) ownLSP.
		delay = LSPCreateGenDelay
	}
	lsp.regenWait = time.AfterFunc(delay,
		func() { db.chgLSPC <- chgLSP{timer: true, pnid: pnid} })

	Debug(DbgFUpd, "%s: OwnLSP pnid %d generation scheduled %s", lsp.li, pnid, delay)

	return lsp
}

// finishSegment update the LSP segment header prior to pushing out.
// send previous buffer to the update process.
func (lsp *ownLSP) finishSegment(payload []byte, i uint8) error {
	lsp.segments[i] = payload

	clns.InitHeader(payload, clns.LSPTypeMap[lsp.db.li])
	hdr := Slicer(payload, clns.HdrCLNSSize, clns.HdrLSPSize)

	lspid := clns.MakeLSPID(lsp.db.sysid, lsp.Pnid, i)

	dblsp := lsp.db.get(lspid[:])

	seqno := uint32(0)
	if dblsp != nil {
		seqno = dblsp.seqNo()
	}

	// Fill in LSP header
	pkt.PutUInt16(hdr[clns.HdrLSPPDULen:], uint16(len(payload)))
	copy(hdr[clns.HdrLSPLSPID:], lspid[:])
	hdr[clns.HdrLSPFlags] = clns.MakeLSPFlags(0, lsp.db.istype)

	lsp.db.incSeqNo(payload, seqno)

	return nil
}

func (db *DB) purgeOwn(pnid, segid uint8) {
	Debug(DbgFUpd, "%s: Purge own segment: %x-%x", db, pnid, segid)

	lspid := clns.MakeLSPID(db.sysid, pnid, segid)
	lsp := db.get(lspid[:])
	if lsp == nil {
		return
	}
	db.initiatePurgeLSP(lsp, false)
}

func (db *DB) addExtISReach(bt *tlv.BufferTrack, c Circuit) error {
	C := make(chan interface{}, 10)
	defer func() {
		// XXX do we need to drain this too?
		close(C)
	}()

	// Request adjacencies from all circuits or a given circuit.
	count := 0
	if c != nil {
		// Request adjacencies from the given circuit
		c.Adjacencies(C, db.li, true)
		count++
	} else {
		// Request adjacencies from all circuits
		for _, c := range db.circuits {
			c.Adjacencies(C, db.li, false)
			count++
		}
	}
	return bt.AddExtISReach(C, count)
}

func (db *DB) addExtIPv4Reach(bt *tlv.BufferTrack) error {
	C := make(chan interface{}, 10)
	defer func() {
		// XXX do we need to drain this too?
		close(C)
	}()

	// Request adjacencies from all circuits or a given circuit.
	count := 0
	// Request adjacencies from all circuits
	for _, c := range db.circuits {
		c.IPv4Reach(C, db.li)
		count++
	}
	return bt.AddExtIPv4Reach(C, count)
}

// regenerate non-pnode ownLSP
// nolint: gocyclo
func (lsp *ownLSP) regenNonPNodeLSP() error {
	Debug(DbgFUpd, "%s: Non-PN OwnLSP Generation starts", lsp.li)

	oldseg := lsp.segments
	lsp.segments = make(map[uint8][]byte)

	bt := tlv.NewBufferTrack(clns.LSPOrigBufSize, clns.HdrCLNSSize+clns.HdrLSPSize, 256,
		func(buf tlv.Data, i uint8) error {
			return lsp.finishSegment(buf, i)
		})

	if lsp.li.ToLevel() == 2 {
		if err := bt.AddAreas(lsp.db.areas); err != nil {
			Debug(DbgFUpd, "Error adding area TLV: %s", err)
			return err
		}
	}
	if err := bt.AddNLPID(lsp.db.nlpid); err != nil {
		Debug(DbgFUpd, "Error adding NLPID TLV: %s", err)
		return err
	}

	// Add Hostname, ignore error.
	if err := bt.AddHostname(lsp.db.hostname); err != nil {
		Info("ERROR: adding Hostname TLV: %s", err)
	}

	if err := bt.AddIntfAddrs(lsp.db.addrs(true)); err != nil {
		return err
	}

	if err := bt.AddIntfAddrs(lsp.db.addrs(false)); err != nil {
		return err
	}

	// IS Reach (don't use)

	if err := lsp.db.addExtISReach(bt, nil); err != nil {
		return err
	}

	if err := lsp.db.addExtIPv4Reach(bt); err != nil {
		return err
	}

	// External Gen App

	if err := bt.Close(); err != nil {
		return err
	}

	// Now purge any unsupported segments.
	Debug(DbgFUpd, "%s: Purge own unsupported segments", lsp.li)
	for segid := range oldseg {
		_, present := lsp.segments[segid]
		if !present {
			lsp.db.purgeOwn(0, segid)
		}
	}
	return nil
}

// purge the LSP we no longer support.
func (lsp *ownLSP) purge() {
	for segid := range lsp.segments {
		lsp.db.purgeOwn(lsp.Pnid, segid)
	}
}

// regenerate pnode ownLSP
func (lsp *ownLSP) regenPNodeLSP() error {
	Debug(DbgFUpd, "%s: PN OwnLSP Generation starts", lsp.li)

	oldseg := lsp.segments
	lsp.segments = make(map[uint8][]byte)

	bt := tlv.NewBufferTrack(clns.LSPOrigBufSize, clns.HdrCLNSSize+clns.HdrLSPSize, 256,
		func(buf tlv.Data, i uint8) error {
			return lsp.finishSegment(buf, i)
		})

	// Ext Reach
	if err := lsp.db.addExtISReach(bt, lsp.c); err != nil {
		return err
	}

	if err := bt.Close(); err != nil {
		return err
	}

	// Now purge any unsupported segments.
	Debug(DbgFUpd, "%s: Purge own unsupported segments", lsp.li)
	for segid := range oldseg {
		_, present := lsp.segments[segid]
		if !present {
			lsp.db.purgeOwn(0, segid)
		}
	}
	return nil
}

// regenLSP regenerates the ownLSP.
func (lsp *ownLSP) regenLSP() error {
	if lsp.Pnid > 0 {
		return lsp.regenPNodeLSP()
	} else {
		return lsp.regenNonPNodeLSP()
	}
}
