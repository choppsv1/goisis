// -*- coding: utf-8 -*-
//
// Copyright (c) 2018, Christian Hopps
// All Rights Reserved.
//
package main

import (
	"fmt"
	"github.com/choppsv1/goisis/clns"
	"github.com/choppsv1/goisis/pkt"
	"github.com/choppsv1/goisis/tlv"
)

type UpdateProcess struct {
	level     int
	lindex    int //  level - 1 for array indexing
	expireC   chan *LSPSegment
	setAllSRM chan *LSPSegment
}

var updProcs = [2]UpdateProcess{
	{1, 0, make(chan *LSPSegment), make(chan *LSPSegment)},
	{2, 1, make(chan *LSPSegment), make(chan *LSPSegment)},
}

func RecvLSP(link *LANLink, frame *RecvFrame, payload []byte, level int, tlvs map[tlv.Type][]tlv.Data) error {
	debug(DbgFPkt, "INFO: Received level-%d LSP on %s", level, link)
	return nil
}

// Expire an LSP Segment who's lifetime has reached zero
func Expire(seg *LSPSegment) {
	updProcs[seg.lindex].expireC <- seg
}

func SetAllSRM(seg *LSPSegment) {
	updProcs[seg.lindex].setAllSRM <- seg
}

func (up *UpdateProcess) deleteLSPSegment(seg *LSPSegment) {
	// Finally remove and delete the segment.
}

func (up *UpdateProcess) updateProcess() {
	for {
		select {
		case seg := <-up.expireC:
			debug(DbgFUpd, " <- %s\n", seg)
			if seg.zeroLife != nil {
				// Purge complete
				if seg.life != nil {
					panic("Non-zero lifetime in zero max age")
				}
				seg.zeroLife = nil
				logit("XXX Removing zero lifetime LSP %s", seg)
				up.deleteLSPSegment(seg)
				return
			}
			if pkt.GetUInt32(seg.lsphdr[clns.HdrLSPSeqNo:]) == 0 {
				panic(fmt.Sprintf("Invalid expire of seqno 0 LSP %s", seg))
			}
			seg.PurgeExpired()
		case seg := <-up.setAllSRM:
			GlbLinkDB.SetAllFlag(seg, SRM, nil)
		}
	}
}
