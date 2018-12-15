//
// -*- coding: utf-8 -*-
//
// December 12 2018, Christian E. Hopps <chopps@gmail.com>
//
//
package update

import (
	"github.com/choppsv1/goisis/clns"
	"time"
	// "github.com/choppsv1/goisis/pkt"
	// xtime "github.com/choppsv1/goisis/time"
	"github.com/choppsv1/goisis/tlv"
)

type LSP struct {
	Pnid     uint // redundant this is the last byte of Nodeid
	li       clns.LIndex
	l        clns.Level
	db       *DB
	c        Circuit
	segments map[uint8][]byte
	genTimer time.Timer
}

// NewLSP creates a new LSP for the router.
func NewLSP(pnid byte, li clns.LIndex, db *DB, c Circuit) *LSP {
	lsp := &LSP{
		Pnid:     uint(pnid),
		li:       li,
		db:       db,
		c:        c,
		segments: make(map[uint8][]byte),
	}

	// Just use this code when we need nodeid
	// copy(lsp.Nodeid[:], GlbSystemID[:])
	// nodeid[clns.SysIDLen] = pnid

	return lsp
}

// newSegBuffer to obtain a new segment buffer, with an initialized header, and
// send previous buffer to the update process.
func (lsp *LSP) finishSegment(buf tlv.Data, i uint) error {
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

	if err := bt.AddIntfAddrs(lsp.db.GetAddrs(true)); err != nil {
		return err
	}

	if err := bt.AddIntfAddrs(lsp.db.GetAddrs(true)); err != nil {
		return err
	}

	// IS Reach (don't use)

	// Ext Reach

	// Prefixes

	// External Gen App
	return nil

}

// regenerate pnode LSP
func (lsp *LSP) regenPNodeLSP() {
	lsp.db.debug("%s: PN LSP Generation starts", lsp.li)

	// Ext Reach
}

// regenLSP regenerates the LSP.
func (lsp *LSP) regenLSP() {
	if lsp.Pnid > 0 {
		lsp.regenPNodeLSP()
	} else {
		lsp.regenNonPNodeLSP()
	}
}
