// -*- coding: utf-8 -*-
//
// December 16 2018, Christian Hopps <chopps@gmail.com>

// Package update implements the update process of the IS-IS routing protocol.
// This file contains the update processes database code.
package update

import (
	"bytes"
	"fmt"
	"github.com/choppsv1/goisis/clns"
	. "github.com/choppsv1/goisis/logging" // nolint
	"github.com/choppsv1/goisis/pkt"
	xtime "github.com/choppsv1/goisis/time"
	"github.com/choppsv1/goisis/tlv"
	"github.com/plar/go-adaptive-radix-tree"
	"time"
)

func (lsp *lspSegment) seqNo() uint32 {
	return pkt.GetUInt32(lsp.hdr[clns.HdrLSPSeqNo:])
}

func (lsp *lspSegment) checkLifetime() uint16 {
	if lsp.life == nil {
		return 0
	}
	return lsp.life.Until()
}

func (lsp *lspSegment) updateLifetime(shave bool) uint16 {
	if lsp.life == nil {
		if pkt.GetUInt16(lsp.hdr[clns.HdrLSPLifetime:]) != 0 {
			panic("Invalid non-zero life with no holdtimer")
		}
		return 0
	}
	lifetime := lsp.life.Until()
	// This is to test flooding
	// if shave {
	// 	if lifetime > 15 {
	// 		lifetime -= 15
	// 	}
	// }
	pkt.PutUInt16(lsp.hdr[clns.HdrLSPLifetime:], lifetime)
	return lifetime
}

func (lsp *lspSegment) cksum() uint16 {
	return pkt.GetUInt16(lsp.hdr[clns.HdrLSPCksum:])
}

func (lsp *lspSegment) flags() clns.LSPFlags {
	return clns.LSPFlags(lsp.hdr[clns.HdrLSPFlags] & clns.LSPFlagMask)
}

// get the lsp segment with the given LSPID or nil if not present.
func (db *DB) get(lspid []byte) *lspSegment {
	v, ok := db.db.Search(lspid)
	if !ok {
		return nil
	}
	return v.(*lspSegment)
}

// newLSPSegment creates a new lspSegment struct
func (db *DB) newLSPSegment(payload []byte, tlvs tlv.Map) *lspSegment {
	hdr := Slicer(payload, clns.HdrCLNSSize, clns.HdrLSPSize)
	lsp := &lspSegment{
		payload: payload,
		hdr:     hdr,
		tlvs:    tlvs,
	}
	copy(lsp.lspid[:], hdr[clns.HdrLSPLSPID:])

	lifetime := pkt.GetUInt16(hdr[clns.HdrLSPLifetime:])
	if db.testPurge {
		lifetime = 30
	}
	lsp.life = xtime.NewHoldTimer(lifetime, func() { db.expireC <- lsp.lspid })
	lsp.isOurs = bytes.Equal(lsp.lspid[:clns.SysIDLen], db.sysid[:])

	db.db.Insert(lsp.lspid[:], lsp)
	db.cacheAdd(lsp.hdr)

	Debug(DbgFUpd, "%s: New LSP: %s", db, lsp)
	return lsp
}

// newLSPSegment creates a new lspSegment struct
func (db *DB) newZeroLSPSegment(lifetime uint16, lspid *clns.LSPID, cksum uint16) *lspSegment {
	lsp := &lspSegment{
		hdr: make([]byte, clns.HdrLSPSize),
	}
	lsp.lspid = *lspid
	copy(lsp.hdr[clns.HdrLSPLSPID:], lsp.lspid[:])
	pkt.PutUInt16(lsp.hdr[clns.HdrLSPLifetime:], lifetime)
	pkt.PutUInt16(lsp.hdr[clns.HdrLSPCksum:], cksum)
	lsp.life = xtime.NewHoldTimer(lifetime, func() { db.expireC <- lsp.lspid })
	lsp.isOurs = bytes.Equal(lsp.lspid[:clns.SysIDLen], db.sysid[:])

	db.db.Insert(lsp.lspid[:], lsp)
	db.cacheAdd(lsp.hdr)

	Debug(DbgFUpd, "%s: New Zero SeqNo LSP: %s", db, lsp)
	return lsp
}

// updateLSPSegment updates an lspSegment with a newer version received on a link.
func (db *DB) updateLSPSegment(lsp *lspSegment, payload []byte, tlvs tlv.Map) {
	Debug(DbgFUpd, "%s: Updating %s", db, lsp)

	// On entering the hold timer has already been stopped by receiveLSP

	// We are replacing the previous PDU payload slice thus we are
	// relinquishing our reference on that previous PDU frame
	lsp.payload = payload
	lsp.hdr = Slicer(payload, clns.HdrCLNSSize, clns.HdrLSPSize)
	lsp.tlvs = tlvs

	db.cacheUpdate(lsp.hdr)

	lifetime := pkt.GetUInt16(lsp.hdr[clns.HdrLSPLifetime:])
	if lifetime == 0 {
		if lsp.life != nil {
			// Timer is stopped. Forget about it.
			lsp.life = nil
		}
		if lsp.zeroLife == nil {
			// New purge.
			Debug(DbgFUpd, "%s: Received Purge LSP %s", db, lsp)
			lsp.zeroLife = xtime.NewHoldTimer(clns.ZeroMaxAge,
				func() { db.expireC <- lsp.lspid })
			// Optional add Purge TLV if missing, need adjacency
			// received on for that.
		} else if lsp.zeroLife.Until() < clns.ZeroMaxAge {
			// Refresh zero age. If we can't reset the timer b/c
			// it's fired/firing just create a new one. We handle it.
			if !lsp.zeroLife.Stop() {
				lsp.zeroLife = xtime.NewHoldTimer(clns.ZeroMaxAge,
					func() { db.expireC <- lsp.lspid })
			} else {
				lsp.zeroLife.Reset(clns.ZeroMaxAge)
			}
		}
		return
	}

	if lsp.life != nil {
		// Reset the hold timer -- XXX are we always supposed to do this?
		lsp.life.Reset(lifetime)
		Debug(DbgFUpd, "%s: Reset hold timer %d for %s", db, lifetime, lsp)
	} else {
		// We should never see both nil we would have deleted it.
		if lsp.zeroLife == nil {
			panic(fmt.Sprintf("WARNING: both life and zeroLife nil for %s", lsp))
		}
		// No need to check if we sotpped as we can handle being
		// called now after update.
		lsp.zeroLife.Stop()
		lsp.zeroLife = nil
		if db.testPurge {
			lifetime = 10
		}
		lsp.life = xtime.NewHoldTimer(lifetime, func() { db.expireC <- lsp.lspid })
		Debug(DbgFUpd, "%s: Reset hold timer for Purged %s", db, lsp)
	}

	Debug(DbgFUpd, "%s: Updated %s", db, lsp)
}

func copyTLV(dst, src []byte) int {
	l := len(src)
	copy(dst, src)
	return l
}

// initiatePurgeLSP initiates a purge of an LSPSegment due to lifetime running
// to zero.
func (db *DB) initiatePurgeLSP(lsp *lspSegment, fromTimer bool) {
	var zeroMaxAge uint16

	// If we still have a timer still stop it if we can.
	if lsp.life == nil {
		zeroMaxAge = clns.ZeroMaxAge
	} else {
		if !fromTimer && !lsp.life.Stop() {
			// Can't stop the timer we will be called again.
			Debug(DbgFUpd, "%s: Can't stop timer for %s let it happen", db, lsp)
			return
		}
		// We hold on to LSPs that we force purge longer.
		zeroMaxAge = clns.MaxAge
		lsp.life = nil
	}

	// Get rid of refresh timer for our own LSP segments.
	if lsp.refresh != nil {
		lsp.refresh.Stop()
		lsp.refresh = nil
	}

	// Update the lifetime to zero if it wasn't already.
	pkt.PutUInt16(lsp.hdr[clns.HdrLSPLifetime:], 0)
	Debug(DbgFUpd, "%s: Purging %s zeroMaxAge: %d", db, lsp, zeroMaxAge)

	if lsp.zeroLife != nil {
		panic("Initiating a purge on a purged LSP.")
	}
	lsp.zeroLife = xtime.NewHoldTimer(zeroMaxAge,
		func() { db.expireC <- lsp.lspid })

	//-----------------------------
	// ISO10589: 7.3.16.4: a, b, c
	//-----------------------------

	// a)
	// db.setsrm <- lsp.lspid
	db.setAllFlag(SRM, lsp.lspid, nil)

	// b) Retain only LSP header + purge TLVs
	var savespace [1024]byte
	tlvp := tlv.Data(savespace[:])

	// Save space for purge TLV
	tlvp = tlvp[2+clns.SysIDLen:]

	// Save other purge OK TLVs
	if lsp.tlvs[tlv.TypeHostname] != nil {
		l := copyTLV(tlvp, lsp.tlvs[tlv.TypeHostname][0])
		tlvp = tlvp[l:]
	}
	if lsp.tlvs[tlv.TypeInstanceID] != nil {
		l := copyTLV(tlvp, lsp.tlvs[tlv.TypeInstanceID][0])
		tlvp = tlvp[l:]
	}
	if lsp.tlvs[tlv.TypeFingerprint] != nil {
		l := copyTLV(tlvp, lsp.tlvs[tlv.TypeFingerprint][0])
		tlvp = tlvp[l:]
	}
	// Purge LSP
	purgetlv := savespace[:]
	purgetlv[0] = byte(tlv.TypePurge)
	purgetlv[1] = byte(clns.SysIDLen)
	copy(purgetlv[2:], db.sysid[:])

	// Shrink LSP Payload
	purgelen := tlv.GetOffset(savespace[:], tlvp)
	pdulen := clns.HdrCLNSSize + clns.HdrLSPSize + purgelen
	Debug(DbgFUpd, "Shrinking lsp.payload %d:%d to %d", len(lsp.payload), cap(lsp.payload), pdulen)

	lsp.payload = lsp.payload[:pdulen]
	Debug(DbgFUpd, "Shrunk lsp.payload to %d:%d", len(lsp.payload), cap(lsp.payload))
	pkt.PutUInt16(lsp.hdr[clns.HdrLSPCksum:], 0)
	pkt.PutUInt16(lsp.hdr[clns.HdrLSPPDULen:], uint16(pdulen))

	// Add back in the purge TLVs
	tlvp = lsp.payload[pdulen-purgelen:]
	copy(tlvp, savespace[:purgelen])
	lsp.tlvs, _ = tlvp.ParseTLV()

	// Update the CSNP cache
	db.cacheUpdate(lsp.hdr)

}

// deleteLSP removes the LSP from the DB.
func (db *DB) deleteLSP(lsp *lspSegment) {
	// Update the CSNP cache
	db.cacheDelete(lsp.hdr)

	Debug(DbgFUpd, "Deleting LSP %s", lsp)
	db.db.Delete(lsp.lspid[:])
}

// Increment the sequence number for one of our own LSP segments, fixup the
// header and inject into DB.
func (db *DB) incSeqNo(payload []byte, seqno uint32) {
	Debug(DbgFUpd, "%s Incrementing Own Seq No 0x%x", db, seqno)

	lspbuf := payload[clns.HdrCLNSSize:]

	seqno++ // XXX deal with rollover.

	lifetime := uint16(clns.MaxAge)
	pkt.PutUInt16(lspbuf[clns.HdrLSPLifetime:], lifetime)
	pkt.PutUInt32(lspbuf[clns.HdrLSPSeqNo:], seqno)
	pkt.PutUInt16(lspbuf[clns.HdrLSPCksum:], 0)
	cksum := clns.Cksum(lspbuf[clns.HdrLSPLSPID:], 13)
	pkt.PutUInt16(lspbuf[clns.HdrLSPCksum:], cksum)

	tlvs, err := tlv.Data(lspbuf[clns.HdrLSPSize:]).ParseTLV()
	if err != nil {
		Debug(DbgFUpd, "%s Invalid TLV from ourselves", db)
		panic("Invalid TLV from ourselves")
	}

	db.receiveLSP(nil, payload, tlvs)
}

// compareLSP we compare against either the LSP header + 2 or an SNPEntry.
func compareLSP(lsp *lspSegment, e []byte) lspCompareResult {
	if lsp == nil {
		return NEWER
	}

	// Do a quick check to see if this is the same memory.
	if tlv.GetOffset(lsp.payload[clns.HdrCLNSSize+clns.HdrLSPLifetime:], e) == 0 {
		return SAME
	}

	nseqno := pkt.GetUInt32(e[tlv.SNPEntSeqNo:])
	oseqno := lsp.seqNo()
	if nseqno > oseqno {
		return NEWER
	} else if nseqno < oseqno {
		return OLDER
	}

	nlifetime := pkt.GetUInt16(e[tlv.SNPEntLifetime:])
	olifetime := lsp.updateLifetime(false)
	if nlifetime == 0 && olifetime != 0 {
		return NEWER
	} else if olifetime == 0 && nlifetime != 0 {
		return OLDER
	}
	return SAME
}

// receiveLSP receives an LSP from flooding
// nolint: gocyclo
func (db *DB) receiveLSP(c Circuit, payload []byte, tlvs tlv.Map) {
	// We input or own LSP here with nil circuit to differentiate.
	fromUs := c == nil

	var lspid clns.LSPID
	copy(lspid[:], payload[clns.HdrCLNSSize+clns.HdrLSPLSPID:])

	lsp := db.get(lspid[:])

	newhdr := Slicer(payload, clns.HdrCLNSSize, clns.HdrLSPSize)
	nlifetime := pkt.GetUInt16(newhdr[clns.HdrLSPLifetime:])
	nseqno := pkt.GetUInt32(newhdr[clns.HdrLSPSeqNo:])

	result := compareLSP(lsp, newhdr[clns.HdrLSPLifetime:])
	isOurs := bytes.Equal(lspid[:clns.SysIDLen], db.sysid[:])

	if isOurs && fromUs {
		// Force newer b/c we may have simply modified the db version of
		// the segment to increment the seqno so it won't seem newer.
		result = NEWER
	}

	Debug(DbgFUpd, "%s: receiveLSP %s 0x%x dblsp %s compare %v isOurs %v fromUs %v", db, lspid, nseqno, lsp, result, isOurs, fromUs)

	// b) If the LSP has zero Remaining Lifetime, perform the actions
	//    described in 7.3.16.4. -- for LSPs not ours this is the same as
	//    normal handling except that we do not add a missing LSP segment,
	//    instead we acknowledge receipt only.

	if isOurs && !fromUs {
		// XXX check all this.
		pnid := lspid[7]
		var unsupported bool
		if pnid == 0 {
			unsupported = false // always support non-pnode LSP
		} else {
			di, set := db.dis[pnid]
			if !set {
				// We haven't run dis election yet, hold off
				// on purging until we have.
				return
			}
			unsupported = lsp == nil || di.c == nil
		}

		// c) Ours, but we don't support, and not expired, perform
		//    7.3.16.4 purge. If ours not supported and expired we will
		//    simply be ACKing the receipt below under e1.
		if unsupported && nlifetime != 0 {
			if lsp != nil {
				// assert c == nil i.e., We have no circuit
				// associated with this DIS circuit ID claiming
				// to be ours.

				// Since we purge when we un-elect ourselves
				// any unsupported but present PN-LSP should be
				// purging.

				// A bad actor might inject a newer seqno for
				// our unsupported purging LSP so we need to
				// update the seqno, and purge again.
				seqno := pkt.GetUInt32(newhdr[clns.HdrLSPSeqNo:])
				if result == NEWER {
					pkt.PutUInt32(lsp.hdr[clns.HdrLSPSeqNo:], seqno)
					// Swap the zero life timer into normal
					// life to cause long zero age purge.
					if lsp.life == nil {
						lsp.life = lsp.zeroLife
						lsp.zeroLife = nil
					}
					db.initiatePurgeLSP(lsp, false)
					return
				}
			} else {
				// Create LSP and then force purge.
				lsp = db.newLSPSegment(payload, tlvs)
				// consolidate or if we need to leave for acks
				db.initiatePurgeLSP(lsp, false)
				return
			}
		}
		// d) Ours, supported and wire is newer, need to increment our
		// copy per 7.3.16.1
		if !unsupported && result == NEWER {
			db.incSeqNo(lsp.payload, nseqno)
			return
		}
	}

	// [ also: ISO 10589 17.3.16.4: a, b ]
	// e1) Newer - update db, flood and acknowledge
	//     [ also: ISO 10589 17.3.16.4: b.1 ]
	if result == NEWER && !fromUs {
		if lsp != nil && lsp.life != nil {
			if !lsp.life.Stop() {
				// This means the LSP segment just expired and we were
				// unable to stop the hold timer b/c we haven't
				// handled the event yet.  We need to recheck
				// NEWER now, it will either remain NEWER or
				// switch to SAME.
				result = compareLSP(lsp, newhdr[clns.HdrLSPLifetime:])
			}
			// else {
			//	We've now stopped the timer we would have
			//	reset it anyway in updateLSPSegment.
			// }
		}
	}

	if result == NEWER {
		if lsp != nil {
			if c != nil {
				Debug(DbgFUpd, "%s: Updating LSP from %s", db, c)
			} else {
				Debug(DbgFUpd, "%s: Updating Own LSP", db)
			}
			db.updateLSPSegment(lsp, payload, tlvs)
		} else {
			if c != nil {
				Debug(DbgFUpd, "%s: Added LSP from %s", db, c)
			} else {
				Debug(DbgFUpd, "%s: Added Own LSP", db)
			}
			if nlifetime == 0 {
				// 17.3.16.4: a
				// XXX send ack on circuit do not retain
				return
			}
			lsp = db.newLSPSegment(payload, tlvs)
		}

		db.setAllFlag(SRM, lsp.lspid, c)
		db.clearFlag(SRM, lsp.lspid, c)
		if c != nil && c.IsP2P() {
			db.setFlag(SSN, lsp.lspid, c)
		}
		db.clearAllFlag(SSN, lsp.lspid, c)

		// Setup/Reset a refresh time for our own LSP segments.
		if fromUs {
			if lsp.refresh != nil {
				// We don't care if we can't stop it, this pathological case
				// just results in an extra seqno increment.
				lsp.refresh.Stop()
			}
			// Refresh when the lifetime values is 3/4 expired.
			refresh := time.Second * time.Duration(nlifetime) * 3 / 4
			// New refresh timer, old one has fired, is stopped or we don't care.
			lsp.refresh = time.AfterFunc(refresh, func() { db.refreshC <- lspid })
			Debug(DbgFUpd, "%s: setting refresh timer for %s to %s", db, lsp, refresh)
		}
	} else if result == SAME {
		// e2) Same - Stop sending and Acknowledge
		//     [ also: ISO 10589 17.3.16.4: b.2 ]
		db.clearAllFlag(SRM, lsp.lspid, nil)
		if c != nil && c.IsP2P() {
			db.setFlag(SSN, lsp.lspid, c)
		}
	} else {
		// e3) Older - Send and don't acknowledge
		//     [ also: ISO 10589 17.3.16.4: b.3 ]
		db.setFlag(SRM, lsp.lspid, c)
		db.clearFlag(SSN, lsp.lspid, c)
		db.clearAllFlag(SRM, lsp.lspid, nil)
	}
}

// nolint: gocyclo
func (db *DB) receiveSNP(c Circuit, complete bool, payload []byte, tlvs tlv.Map) {
	// -------------------------------------------------------------
	// ISO10589: 7.3.15.2 "Action on receipt of sequence numbers PDU
	// -------------------------------------------------------------
	// a.1-5 already done in receive 6 Check SNPA from an adj (use function)
	// a.[78] check password/auth

	var mentioned art.Tree
	if complete {
		mentioned = art.New()
	}

	// ISO10589: 8.3.15.2.b
	entries, err := tlvs.SNPEntryValues()
	if err != nil {
		Debug(DbgFUpd, "%s: Error parsing SNP Entries: %s", db, err)
		return
	}

	for _, e := range entries {
		var elspid clns.LSPID
		copy(elspid[:], e[tlv.SNPEntLSPID:])

		lsp := db.get(elspid[:])
		if complete {
			mentioned.Insert(elspid[:], true)
		}

		// 7.3.15.2: b1
		result := compareLSP(lsp, e)
		switch result {
		case SAME:
			if c.IsP2P() {
				// 7.3.15.2: b2 ack received, stop sending on p2p
				db.clearFlag(SRM, elspid, c)
			}
		case OLDER:
			// 7.3.15.2: b3 flood newer from our DB
			db.clearFlag(SSN, elspid, c)
			db.setFlag(SRM, elspid, c)
		case NEWER:
			lifetime := pkt.GetUInt16(e[tlv.SNPEntLifetime:])
			seqno := pkt.GetUInt32(e[tlv.SNPEntSeqNo:])
			cksum := pkt.GetUInt16(e[tlv.SNPEntCksum:])
			if lsp != nil {
				Debug(DbgFUpd, "%s: SNP Entry [life:0x%d,seqno:0x%x,cksum:0x%x] newer than LSP: %s",
					db, lifetime, seqno, cksum, lsp)

				// 7.3.15.2: b4 Request newer.
				db.setFlag(SSN, elspid, c)
				if c.IsP2P() {
					db.clearFlag(SRM, elspid, c)
				}
			} else {
				// 7.3.15.2: b5 Add zero seqno segment for missing
				Debug(DbgFUpd, "%s: SNP Entry [life:0x%d,seqno:0x%x,cksum:0x%x] for missing LSPID: %s",
					db, lifetime, seqno, cksum, elspid)
				if lifetime != 0 && seqno != 0 && cksum != 0 {
					_ = db.newZeroLSPSegment(lifetime, &elspid, cksum)
					db.setFlag(SSN, elspid, c)
				}

			}
		}
	}
	if !complete {
		return
	}

	Debug(DbgFUpd, "%s: CSNP: Look for we have, they don'ts", db)

	// 7.3.15.2.c Set SRM for all LSP we have that were not mentioned.
	hdr := Slicer(payload, clns.HdrCLNSSize, clns.HdrCSNPSize)
	startid := Slicer(hdr, clns.HdrCSNPStartLSPID, clns.LSPIDLen)
	endid := Slicer(hdr, clns.HdrCSNPStartLSPID, clns.LSPIDLen)

	for it := db.db.Iterator(); it.HasNext(); {
		var lspid clns.LSPID
		node, _ := it.Next()
		copy(lspid[:], node.Key())

		if bytes.Compare(lspid[:], startid) < 0 {
			continue
		}
		if bytes.Compare(lspid[:], endid) > 0 {
			break
		}
		_, found := mentioned.Search(lspid[:])
		if !found {
			lsp := db.get(lspid[:])

			Debug(DbgFUpd, "%s: CSNP: Missing %s", db, lsp)
			if lsp.seqNo() == 0 {
				Debug(DbgFUpd, "%s: CSNP: Skipping zero seqno: LSPID: %s", db, lspid)
				continue
			}
			if lsp.checkLifetime() == 0 {
				Debug(DbgFUpd, "%s: CSNP: Skipping zero lifetime: LSPID: %s", db, lspid)
				continue
			}
			db.setFlag(SRM, lspid, c)
		}
	}

}
