// -*- coding: utf-8 -*-
//
// December 16 2018, Christian Hopps <chopps@gmail.com>
//

// Package update implements the update process of the IS-IS routing protocol.
// This file contains an implementation of a CSNP cache. PATENT: xxx
package update

import (
	"bytes"
	"encoding/binary"
	"github.com/choppsv1/goisis/clns"
	"github.com/choppsv1/goisis/pkt"
	"github.com/choppsv1/goisis/tlv"
)

var endLSPID = clns.LSPID{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

type csnpCache struct {
	pdus [][]byte
	mtu  uint
}

func startID(pdu []byte) (lspid clns.LSPID) {
	copy(lspid[:], Slicer(pdu, clns.HdrCLNSSize+clns.HdrCSNPStartLSPID, clns.LSPIDLen))
	return
}

func endID(pdu []byte) (lspid clns.LSPID) {
	copy(lspid[:], Slicer(pdu, clns.HdrCLNSSize+clns.HdrCSNPEndLSPID, clns.LSPIDLen))
	return
}

func isEndCsnp(pdu []byte) bool {
	return bytes.Equal(endLSPID[:],
		Slicer(pdu, clns.HdrCLNSSize+clns.HdrCSNPEndLSPID, clns.LSPIDLen))

}

func nextLSPID(lspid clns.LSPID) clns.LSPID {
	binary.BigEndian.PutUint64(lspid[:], binary.BigEndian.Uint64(lspid[:])+1)
	return lspid
}

func (db *DB) nextCsnpPdu() []byte {
	count := len(db.cache.pdus)
	pdu := make([]byte, db.cache.mtu)
	clns.InitHeader(pdu, clns.CSNPTypeMap[db.li])
	csnp := pdu[clns.HdrCLNSSize:]
	copy(csnp[clns.HdrCSNPSrcID:], db.sysid[:])

	var startid clns.LSPID
	if count > 0 {
		startid = nextLSPID(endID(db.cache.pdus[count-1]))
	}
	copy(csnp[clns.HdrCSNPStartLSPID:], startid[:])

	// Find first LSP equal to or great than start
	// XXX we have a tree, we need to use it here!

	var lsp *lspSegment
	it := db.db.Iterator()
	for it.HasNext() {
		node, _ := it.Next()
		key := node.Key()
		if bytes.Compare(key, startid[:]) >= 0 {
			lsp = node.Value().(*lspSegment)
			break
		}
	}

	// Fill with LSPID
	endp := csnp[clns.HdrCSNPSize:]
	if lsp != nil {
		track, _ := tlv.Open(endp, tlv.TypeSNPEntries, nil)

		p, _ := track.Alloc(tlv.SNPEntSize)
		lsp.updateLifetime(true)
		copy(p, lsp.hdr[clns.HdrLSPLifetime:clns.HdrLSPFlags])

		for it.HasNext() {
			node, _ := it.Next()
			lsp = node.Value().(*lspSegment)

			p, err := track.Alloc(tlv.SNPEntSize)
			if err != nil {
				// Assert that this is the error we expect.
				_ = err.(tlv.ErrNoSpace)
				break
			}
			lsp.updateLifetime(true)
			copy(p, lsp.hdr[clns.HdrLSPLifetime:clns.HdrLSPFlags])
		}
		endp = track.Close()
	}

	// If more LSP then store LSPID as end or endID if no more.
	if it.HasNext() {
		copy(csnp[clns.HdrCSNPEndLSPID:], lsp.lspid[:])
	} else {
		copy(csnp[clns.HdrCSNPEndLSPID:], endLSPID[:])
	}

	// Finally trim the payload and set the PDULen
	pdulen := tlv.GetOffset(pdu, endp)
	pkt.PutUInt16(csnp[clns.HdrCSNPPDULen:], uint16(pdulen))
	return pdu[pdulen:]
}

// cachePdu gets the cache entry (or creates it), it also returns what actual
// index that was fetched.
func (db *DB) cachePdu(i int) ([]byte, int) {
	count := len(db.cache.pdus)
	if i < count {
		return db.cache.pdus[i], i
	}

	// If the cache is full, just wrap.
	if count > 0 && isEndCsnp(db.cache.pdus[count-1]) {
		return db.cache.pdus[0], 0
	}

	// add next PDU to the cache.
	db.cache.pdus = append(db.cache.pdus, db.nextCsnpPdu())
	return db.cache.pdus[count], count
}

// locate the index of the PDU that contains (or should contain) this LSP entry.
func (db *DB) cacheLocate(lsphdr []byte) int {
	lspid := Slicer(lsphdr, clns.HdrLSPLSPID, clns.LSPIDLen)
	// Should use bi-secting algorithm
	for i, pdu := range db.cache.pdus {
		start := Slicer(pdu, clns.HdrCLNSSize+clns.HdrCSNPStartLSPID, clns.LSPIDLen)
		end := Slicer(pdu, clns.HdrCLNSSize+clns.HdrCSNPEndLSPID, clns.LSPIDLen)
		sc := bytes.Compare(lspid, start)
		if sc < 0 {
			// We start looking from the beginning so must be missing
			return -1
		}
		if bytes.Compare(lspid, end) < 0 {
			// We've found the PDU.
			return i
		}
	}
	return -1
}

func (db *DB) cacheAdd(lsphdr []byte) {
	// We want to just invalidate a given PDU and always reserve some slop
	// for insert/delete, probably should indicate type of change in API.

	// XXX for now very simple just flush the entries PDU and all beyond
	i := db.cacheLocate(lsphdr)
	if i < 0 {
		db.cache.pdus = nil
	} else {
		db.cache.pdus = db.cache.pdus[:i]
	}
}

func (db *DB) cacheDelete(lsphdr []byte) {
	// We want to just invalidate a given PDU and always reserve some slop
	// for insert/delete, probably should indicate type of change in API.

	// XXX for now very simple just flush the entries PDU and all beyond
	i := db.cacheLocate(lsphdr)
	if i < 0 {
		db.cache.pdus = nil
	} else {
		db.cache.pdus = db.cache.pdus[:i]
	}
}

func (db *DB) cacheUpdate(lsphdr []byte) {
	// Locate the PDU and update the entry.

	// XXX for now very simple just flush the entries PDU and all beyond
	i := db.cacheLocate(lsphdr)
	if i < 0 {
		db.cache.pdus = nil
	} else {
		db.cache.pdus = db.cache.pdus[:i]
	}
}
