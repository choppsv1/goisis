// -*- coding: utf-8 -*-
//
// Copyright (c) 2018, Christian Hopps
// All Rights Reserved.
//
// Implement the IS-IS hello procotol
//
package main

import (
	"bytes"
	"fmt"
	"github.com/choppsv1/goisis/clns"
	"github.com/choppsv1/goisis/pkt"
	"github.com/choppsv1/goisis/tlv"
	"time"
)

// StartLANHellos starts a go routine to send hellos and elect DIS
func StartLANHellos(link *LinkLAN, interval uint, quit <-chan bool) {

	debug(DbgFPkt, "Sending hellos on %s with interval %d", link, interval)
	ival := time.Second * time.Duration(interval)
	ticker := time.NewTicker(ival) // XXX replace with jittered timer.
	go sendLANHellos(ticker.C, link, quit)
}

// sendLANHellos is a go routine that sends hellos based using a ticker
// It also processes DIS update events.
func sendLANHellos(tickC <-chan time.Time, link *LinkLAN, quit <-chan bool) {
	disWaiting := DISEventTimer // First wait for timer event
	sendLANHello(link)
	debug(DbgFPkt, "Sent initial IIH on %s entering ticker loop", link)
	for {
		select {
		case <-quit:
			debug(DbgFPkt, "Stop sending IIH on %s", link)
			return
		case e := <-link.disInfoChanged:
			if e != disWaiting {
				debug(DbgFDIS, "INFO: Suppress DIS event %s on %s", e, link)
			} else {
				debug(DbgFDIS, "INFO: Process DIS event %s on %s", e, link)
				disWaiting = DISEventInfo // now wait for normal info changes.
				link.disElect()
			}
		case <-tickC:
			sendLANHello(link)
		}
	}
}

func sendLANHello(link *LinkLAN) error {
	var err error
	var pdutype clns.PDUType

	debug(DbgFPkt, "Sending IIH on %s", link)

	if link.l == 1 {
		pdutype = clns.PDUTypeIIHLANL1
	} else {
		pdutype = clns.PDUTypeIIHLANL2
	}

	// XXX we want the API to return payload here and later we convert frame
	// in close so that we aren't dependent on ethernet
	etherp, _, iihp, endp := link.circuit.OpenPDU(pdutype, clns.AllLxIS[link.li])

	// ----------
	// IIH Header
	// ----------

	iihp[clns.HdrIIHLANCircType] = uint8(link.l)
	copy(iihp[clns.HdrIIHLANSrcID:], GlbSystemID)
	pkt.PutUInt16(iihp[clns.HdrIIHLANHoldTime:],
		uint16(link.helloInt*link.holdMult))
	iihp[clns.HdrIIHLANPriority] = byte(clns.DefHelloPri) & 0x7F
	copy(iihp[clns.HdrIIHLANLANID:], link.lanID[:])

	// --------
	// Add TLVs
	// --------

	if link.l == 1 {
		endp, err = tlv.AddArea(endp, GlbAreaID)
		if err != nil {
			debug(DbgFPkt, "Error adding area TLV: %s", err)
			return err
		}
	}

	endp, err = tlv.AddNLPID(endp, GlbNLPID)
	if err != nil {
		debug(DbgFPkt, "Error adding NLPID TLV: %s", err)
		return err
	}

	if len(link.circuit.v4addrs) != 0 {
		endp, err = tlv.AddIntfAddrs(endp, link.circuit.v4addrs)
		if err != nil {
			return err
		}
	}
	if len(link.circuit.v6addrs) != 0 {
		endp, err = tlv.AddIntfAddrs(endp, link.circuit.v6addrs)
		if err != nil {
			return err
		}
	}

	endp, err = tlv.AddAdjSNPA(endp, link.adjdb.GetAdjSNPA())
	if err != nil {
		debug(DbgFPkt, "Error Adding SNPA: %s", err)
		return err
	}

	// Pad to MTU
	for cap(endp) > 1 {
		endp, err = tlv.AddPadding(endp)
		if err != nil {
			debug(DbgFPkt, "Error adding Padding TLVs: %s", err)
			return err
		}
	}

	// Send the packet
	link.circuit.outpkt <- link.circuit.ClosePDU(etherp, endp)

	return nil
}

// ErrIIH is a general error in IIH packet processing
type ErrIIH string

func (e ErrIIH) Error() string {
	return fmt.Sprintf("ErrIIH: %s", string(e))
}

// RecvLANHello receives IIH from on a given LAN link
func RecvLANHello(link Link, pdu *RecvPDU, l clns.Level) error {
	debug(DbgFPkt, "IIH: processign from %s", pdu.src)

	tlvs := pdu.tlvs

	// For level 1 we must be in the same area.
	if l == 1 {
		// Expect 1 and only 1 Area TLV
		atlv := tlvs[tlv.TypeAreaAddrs]
		if len(atlv) != 1 {
			return ErrIIH(fmt.Sprintf("INFO: areaMismatch: Incorrect area TLV count: %d", len(atlv)))
		}
		addrs, err := atlv[0].AreaAddrsValue()
		if err != nil {
			return err
		}

		matched := false
		for _, addr := range addrs {
			if bytes.Equal(GlbAreaID, addr) {
				matched = true
				break
			}
		}
		if !matched {
			return ErrIIH(fmt.Sprintf("TRAP areaMismatch: no matching areas"))
		}
	}

	return link.UpdateAdj(pdu)
}
