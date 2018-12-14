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
	// "github.com/choppsv1/goisis/tlv"
)

type Segment struct {
}

type LSP struct {
	Nodeid   clns.NodeID
	Pnid     uint // redundant this is the last byte of Nodeid
	li       clns.LIndex
	l        clns.Level
	cdb      *CircuitDB
	c        Circuit
	segments map[uint]Segment
	genTimer time.Timer
}

// NewLSP creates a new LSP for the router.
func NewLSP(nodeid clns.Nodeid, li clns.LIndex, cdb *CircuitDB, c Circuit) *LSP {
	lsp := &LSP{
		Nodeid:   nodeid,
		Pnid:     nodeid[clns.SysIDLen],
		li:       li,
		cdb:      cdb,
		c:        c,
		segments: make(map[uint][]byte, 0, 256),
	}
	return lsp
}

// newSegBuffer to obtain a new segment buffer, with an initialized header, and
// send previous buffer to the update process.
func (lsp *LSP) newSegBuffer() {
}

// regenerate non-pnode LSP
func (lsp *LSP) regenNonPNodeLSP() {
	debug(dbgFLSP, "%s: Non-PN LSP Generation starts", lsp.li)

	if lsp.li.ToLevel() == 2 {
		if err := bt.AddAreas(GlbAreaIDs); err != nil {
			debug(DbgFPkt, "Error adding area TLV: %s", err)
			return err
		}
	}
	if err = bt.AddNLPID(GlbNLPID); err != nil {
		debug(DbgFPkt, "Error adding NLPID TLV: %s", err)
		return err
	}

	// Add Hostname, ignore error.
	if err = bt.AddHostname(GlbHostname); err != nil {
		// XXX warning instead of debug?
		debug(DbgFPkt, "Error adding Hostname TLV: %s", err)
	}

	if err = bt.AddIntfAddrs(lsp.cdb.GetIPv4Addrs()); err != nil {
		return err
	}

	if err = bt.AddIntfAddrs(lsp.cdb.GetIPv6Addrs()); err != nil {
		return err
	}

	// IS Reach (don't use)

	// Ext Reach

	// Prefixes

	// External Gen App

}

// regenerate pnode LSP
func (lsp *LSP) regenPNodeLSP() {
	debug(dbgFLSP, "%s: PN LSP Generation starts", lsp.li)

	// Ext Reach
}
