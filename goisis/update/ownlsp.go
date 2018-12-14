//
// -*- coding: utf-8 -*-
//
// December 12 2018, Christian E. Hopps <chopps@gmail.com>
//
//
package main

import (
	"github.com/choppsv1/goisis/clns"
	"time"
	// "github.com/choppsv1/goisis/pkt"
	// xtime "github.com/choppsv1/goisis/time"
	"github.com/choppsv1/goisis/tlv"
)

type Segment struct {
}

type LSP struct {
	Pnid     uint // redundant this is the last byte of Nodeid
	li       clns.LIndex
	l        clns.Level
	cdb      *CircuitDB
	c        Circuit
	segments map[uint8][]byte
	genTimer time.Timer
}

// NewLSP creates a new LSP for the router.
func NewLSP(pnid byte, li clns.LIndex, cdb *CircuitDB, c Circuit) *LSP {
	lsp := &LSP{
		Pnid:     uint(pnid),
		li:       li,
		cdb:      cdb,
		c:        c,
		segments: make(map[uint8][]byte),
		// genTimer: time.NewTimer(2),
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
	debug(DbgFLSP, "%s: Non-PN LSP Generation starts", lsp.li)

	bt := tlv.NewBufferTrack(clns.LSPOrigBufSize, clns.HdrCLNSSize+clns.HdrLSPSize, 256,
		func(buf tlv.Data, i uint) error {
			return lsp.finishSegment(buf, i)
		})

	if lsp.li.ToLevel() == 2 {
		if err := bt.AddAreas(GlbAreaIDs); err != nil {
			debug(DbgFPkt, "Error adding area TLV: %s", err)
			return err
		}
	}
	if err := bt.AddNLPID(GlbNLPID); err != nil {
		debug(DbgFPkt, "Error adding NLPID TLV: %s", err)
		return err
	}

	// Add Hostname, ignore error.
	if err := bt.AddHostname(GlbHostname); err != nil {
		// XXX warning instead of debug?
		debug(DbgFPkt, "Error adding Hostname TLV: %s", err)
	}

	if err := bt.AddIntfAddrs(lsp.cdb.GetAddrs(true)); err != nil {
		return err
	}

	if err := bt.AddIntfAddrs(lsp.cdb.GetAddrs(true)); err != nil {
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
	debug(DbgFLSP, "%s: PN LSP Generation starts", lsp.li)

	// Ext Reach
}
