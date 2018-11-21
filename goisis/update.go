// -*- coding: utf-8 -*-
//
// Copyright (c) 2018, Christian Hopps
// All Rights Reserved.
//
package main

// import (
// 	"fmt"
// 	"github.com/choppsv1/goisis/clns"
// 	"github.com/choppsv1/goisis/pkt"
// 	"github.com/choppsv1/goisis/tlv"
// )

// // LSPDB
// type LSPDB map[clns.LSPID]*LSPSegment

// type AllFlagData struct {
// 	set    bool
// 	flag   SxxFlag
// 	lspid  clns.LSPID
// 	butnot Link
// }

// type RecvLSPData struct {
// 	link    Link
// 	payload []byte
// 	tlvs    tlv.TLVMap
// }

// type UpdateProcess struct {
// 	level   clns.Level
// 	lindex  clns.LIndex
// 	lspdb   LSPDB
// 	expireC chan clns.LSPID
// 	lspC    chan RecvLSPData
// 	flagsC  chan AllFlagData
// }

// var updProcs = [2]UpdateProcess{
// 	{1, 0, make(LSPDB), make(chan clns.LSPID), make(chan RecvLSPData), make(chan AllFlagData)},
// 	{2, 1, make(LSPDB), make(chan clns.LSPID), make(chan RecvLSPData), make(chan AllFlagData)},
// }

// // ErrIIH is a general error in IIH packet processing
// type ErrLSP string

// func (e ErrLSP) Error() string {
// 	return fmt.Sprintf("ErrLSP: %s", string(e))
// }

// func RecvLSP(link *LANLink, frame *RecvFrame, payload []byte, level clns.Level, tlvs tlv.TLVMap) error {
// 	debug(DbgFPkt, "INFO: Received level-%d LSP on %s", level, link)

// 	if len(payload) > clns.LSPRecvBufSize {
// 		// ISO 7.3.14.2 - Treat as invalid checksum
// 		// logger.info("TRAP corruptedLSPReceived: {} dropping", link)
// 		logit(fmt.Sprintf("TRAP corruptedLSPReceived(len): %s dropping", link))
// 		// XXX should be error?
// 		return nil
// 	}

// 	// ------------------------------------------------------------
// 	// ISO10589: 7.3.15.1 "Action on receipt of a link state PDU"
// 	// ------------------------------------------------------------

// 	// 1-8 done in receive by the link code

// 	// 9)
// 	btlv := tlvs[tlv.TypeLspBufSize]
// 	if btlv != nil {
// 		if len(btlv) != 1 {
// 			return ErrLSP(fmt.Sprintf("INFO: Incorrect LSPBufSize TLV count: %d", len(btlv)))
// 		}
// 		val, err := btlv[0].LSPBufSizeValue()
// 		if err != nil {
// 			return err
// 		}
// 		if val != clns.LSPOrigBufSize {
// 			return ErrLSP(fmt.Sprintf("TRAP: originatingLSPBufferSizeMismatch: %d", val))
// 		}
// 	}

// 	// Everything is valid so send to the update process to finish.
// 	updProcs[level.ToIndex()].lspC <- RecvLSPData{link, payload, tlvs}

// 	return nil
// }

// // -------------
// // SRM/SSN Flags
// // -------------

// func SetAllSRM(seg *LSPSegment, butnot Link) {
// 	updProcs[seg.lindex].flagsC <- AllFlagData{true, SRM, seg.lspid, butnot}
// }

// func SetAllSSN(seg *LSPSegment, butnot Link) {
// 	updProcs[seg.lindex].flagsC <- AllFlagData{true, SSN, seg.lspid, butnot}
// }

// func ClearAllSRM(seg *LSPSegment, butnot Link) {
// 	updProcs[seg.lindex].flagsC <- AllFlagData{false, SRM, seg.lspid, butnot}
// }

// func ClearAllSSN(seg *LSPSegment, butnot Link) {
// 	updProcs[seg.lindex].flagsC <- AllFlagData{false, SSN, seg.lspid, butnot}
// }

// func (up *UpdateProcess) setFlags(allFlag AllFlagData) {
// 	debug(DbgFUpd, " <-setAll %d %s\n", allFlag.flag, allFlag.lspid)
// 	seg, ok := up.lspdb[allFlag.lspid]
// 	if !ok {
// 		debug(DbgFUpd, "Warning: <-setAll %s not present",
// 			allFlag.lspid)
// 		return
// 	}
// 	GlbLinkDB.SetAllFlag(seg, SRM, allFlag.butnot)
// }

// func (up *UpdateProcess) clearFlags(allFlag AllFlagData) {
// 	debug(DbgFUpd, " <-clearAll %d %s\n", allFlag.flag, allFlag.lspid)
// 	seg, ok := up.lspdb[allFlag.lspid]
// 	if !ok {
// 		debug(DbgFUpd, "Warning: <-clearAll %s not present",
// 			allFlag.lspid)
// 		return
// 	}
// 	GlbLinkDB.ClearAllFlag(seg, SRM, allFlag.butnot)
// }

// // ----------------------------
// // Expiring/Purging/Delete LSPs
// // ----------------------------

// // Expire an LSP Segment who's lifetime has reached zero
// func Expire(lindex uint8, lspid clns.LSPID) {
// 	updProcs[lindex].expireC <- lspid
// }

// func (up *UpdateProcess) deleteLSPSegment(lspid clns.LSPID) {
// 	// Finally remove and delete the segment.
// 	if _, ok := up.lspdb[lspid]; ok {
// 		delete(up.lspdb, lspid)
// 	} else {
// 		debug(DbgFUpd, "Warning: deleteLSPSegment %s not present", lspid)
// 	}
// }

// // updateLSP from received LSPSegment
// func (up *UpdateProcess) updateLSP(lspData *RecvLSPData) {

// 	payload := lspData.payload
// 	lspHdr := Slicer(payload, clns.HdrCLNSSize, clns.HdrLSPSize)
// 	// tlvs := lspData.tlvs

// }

// // updateProcess - Go routine implementing the IS-IS Update Process.
// func (up *UpdateProcess) updateProcess() {
// 	for {
// 		select {
// 		case lspData := <-up.lspC:
// 			up.updateLSP(&lspData)
// 			return
// 		case lspid := <-up.expireC:
// 			debug(DbgFUpd, " <-expireC %s\n", lspid)
// 			seg, ok := up.lspdb[lspid]
// 			if !ok {
// 				debug(DbgFUpd, "Warning: <-expireC %s not present",
// 					lspid)
// 				return
// 			}
// 			if seg.life != nil && seg.life.Until() != 0 {
// 				debug(DbgFUpd, "<-expireC: %s ressurected", seg)
// 				return
// 			}
// 			if seg.zeroLife != nil {
// 				// Purge complete
// 				if seg.life != nil {
// 					panic("Non-zero lifetime in zero max age")
// 				}
// 				seg.zeroLife = nil
// 				logit("XXX Removing zero lifetime LSP %s", seg)
// 				up.deleteLSPSegment(seg.lspid)
// 				return
// 			}
// 			if pkt.GetUInt32(seg.lsphdr[clns.HdrLSPSeqNo:]) == 0 {
// 				panic(fmt.Sprintf("Invalid expire of seqno 0 LSP %s", seg))
// 			}
// 			seg.PurgeExpired()
// 		case allFlag := <-up.flagsC:
// 			if allFlag.set {
// 				up.setFlags(allFlag)
// 			} else {
// 				up.clearFlags(allFlag)
// 			}
// 		}

// 		// Now walk all links and send an LSP segment
// 		for _, link := range GlbLinkDB.links {
// 			for lspid, _ := range link.GetFlags(up.lindex, SRM) {
// 				seg, ok := up.lspdb[lspid.(clns.LSPID)]
// 				if ok {
// 					link.HandleSRM(seg)
// 				}
// 				break
// 			}
// 		}

// 		// Now walk all the links and send SNP -- XXX only for P2P?
// 		for _, link := range GlbLinkDB.links {
// 			for lspid, _ := range link.GetFlags(up.lindex, SSN) {
// 				seg, ok := up.lspdb[lspid.(clns.LSPID)]
// 				if ok {
// 					link.HandleSSN(seg)
// 				}
// 				break
// 			}
// 		}
// 	}
// }
