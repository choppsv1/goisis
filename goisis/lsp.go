// -*- coding: utf-8 -*-
//
// Copyright (c) 2018, Christian Hopps
// All Rights Reserved.
//
// Functions for managing LSPs
//
package main

// import (
// 	"fmt"
// 	"github.com/choppsv1/goisis/clns"
// 	"github.com/choppsv1/goisis/pkt"
// 	"github.com/choppsv1/goisis/tlv"
// )

// const (
// 	LSP_ZERO_MAX_AGE = 60   // Age for LSP pior to deleting.
// 	LSP_MAX_AGE      = 1200 // Normal age for new LSP.
// )

// type LSPSegment struct {
// 	life     *HoldTimer
// 	zeroLife *HoldTimer
// 	isAck    bool
// 	level    clns.Level
// 	lindex   clns.LIndex
// 	lspid    clns.LSPID
// 	lsphdr   []byte
// 	payload  []byte
// 	tlvs     map[tlv.Type][]tlv.Data
// }

// // Slicer grabs a slice from a byte slice given a start and length.
// func Slicer(b []byte, start int, length int) []byte {
//       return b[start : start+length]
// }

// // NewLSPSegment creates a new LSP segment
// func NewLSPSegment(frame *RecvFrame, payload []byte, level clns.Level, tlvs map[tlv.Type][]tlv.Data) (*LSPSegment, error) {
// 	seg := &LSPSegment{
// 		level:   level,
// 		lindex:  level.ToIndex(),
// 		payload: payload,
// 		lsphdr:  Slicer(payload, clns.HdrCLNSSize, clns.HdrLSPSize),
// 		tlvs:    tlvs,
// 	}
// 	copy(seg.lspid[:], seg.lsphdr[clns.HdrLSPLSPID:])

// 	// XXX what if it's zero? I think we set to LSP_MAX_AGE but for zero timer

// 	seg.life = NewHoldTimer(pkt.GetUInt16(seg.lsphdr[clns.HdrLSPLifetime:]),
// 		func() { Expire(seg.lindex, seg.lspid) })

// 	return seg, nil
// }

// func (seg *LSPSegment) String() string {
// 	return fmt.Sprintf("LSP(id:%s seqno:%010x lifetime:%d cksum:%06x)",
// 		clns.LSPIDString(seg.lsphdr[clns.HdrLSPLSPID:]),
// 		pkt.GetUInt32(seg.lsphdr[clns.HdrLSPSeqNo:]),
// 		pkt.GetUInt16(seg.lsphdr[clns.HdrLSPLifetime:]),
// 		pkt.GetUInt16(seg.lsphdr[clns.HdrLSPCksum:]))
// }

// // PurgeExpired is called when the holdtimer has fired to initiate a purge.
// func (seg *LSPSegment) PurgeExpired() {

// 	// ---------------------------
// 	// ISO10589: 7.3.16.4: a, b, c
// 	// ---------------------------

// 	// a)
// 	SetAllSRM(seg, nil)

// 	// b) Retain only LSP header.
// 	// XXX Add in PurgeTLV and others
// 	seg.payload = seg.payload[:clns.HdrCLNSSize+clns.HdrLSPSize]
// 	pkt.PutUInt16(seg.payload[clns.HdrLSPCksum:], 0)
// 	pdulen := uint32(len(seg.payload) - clns.HdrLLCSize)
// 	pkt.PutUInt32(seg.payload[clns.HdrLSPCksum:], pdulen)

// 	// c) Retain for ZERO_MAX_AGE
// 	seg.life, seg.zeroLife = nil, seg.life
// 	seg.life.Reset(LSP_ZERO_MAX_AGE)
// }
