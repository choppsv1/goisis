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
	"net"
	"time"
)

// StartHelloProcess starts a go routine to send and receive hellos and possibly
// elect DIS (on LAN)
func StartHelloProcess(link *LinkLAN, interval uint, quit <-chan bool) {
	debug(DbgFPkt, "Sending hellos on %s with interval %d", link, interval)
	ival := time.Second * time.Duration(interval)
	ticker := time.NewTicker(ival) // XXX replace with jittered timer.
	go helloProcess(ticker.C, link, quit)
}

// XXX rename Hello Process
// sendLANHellos is a go routine that sends hellos based using a ticker
// It also processes DIS update events.
func helloProcess(tickC <-chan time.Time, link *LinkLAN, quit <-chan bool) {
	disWaiting := true

	sendLANHello(link)

	debug(DbgFPkt, "Sent initial IIH on %s entering hello loop", link)
	for {
		var rundis bool
		select {
		case <-quit:
			debug(DbgFPkt, "Stop sending IIH on %s", link)
			return
		case pdu := <-link.iihpkt:
			rundis = pdu.link.RecvHello(pdu)
		case srcid := <-link.expireC:
			// Expire an adjancency.
			a := link.srcidMap[srcid]
			if a == nil {
				debug(DbgFDIS, "Adj for %s on %s is gone.", srcid, link)
				break
			}
			// If the adjacency was up then we need to rerun DIS election.
			rundis = a.State == AdjStateUp
			delete(link.snpaMap, a.snpa)
			delete(link.srcidMap, a.sysid)
		case <-link.disTimer.C:
			debug(DbgFDIS, "INFO: DIS timer fires %s", link)
			disWaiting = false
			rundis = true
		case <-tickC:
			sendLANHello(link)
		}

		if rundis {
			if disWaiting {
				debug(DbgFDIS, "INFO: Suppress DIS elect on %s", link)
			} else {
				debug(DbgFDIS, "INFO: DIS info changed on %s", link)
				link.disElect()
			}
		}
	}
}

// getAdjSNPA returns an list of SNPA for all non-DOWN adjacencies
func (link *LinkLAN) getAdjSNPA() []net.HardwareAddr {
	alist := make([]net.HardwareAddr, 0, len(link.srcidMap))
	for _, a := range link.srcidMap {
		if a.State != AdjStateDown {
			alist = append(alist, a.snpa[:])
		}
	}
	return alist
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
	iihp[clns.HdrIIHLANPriority] = byte(link.priority) & 0x7F
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

	endp, err = tlv.AddAdjSNPA(endp, link.getAdjSNPA())
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

// ===================
// LAN Hello Functions
// ===================

// RecvLANHello receives IIH from on a given LAN link
func (link *LinkLAN) RecvHello(pdu *RecvPDU) bool {
	debug(DbgFPkt, "IIH: processign from %s", pdu.src)
	var rundis bool

	tlvs := pdu.tlvs

	// ISO10589 8.4.2.1.c auth.

	// For level 1 we must be in the same area.
	if pdu.l == 1 {
		// Expect 1 and only 1 Area TLV
		atlv := tlvs[tlv.TypeAreaAddrs]
		if len(atlv) != 1 {
			logit(fmt.Sprintf("INFO: areaMismatch: Incorrect area TLV count: %d", len(atlv)))
			return rundis
		}
		addrs, err := atlv[0].AreaAddrsValue()
		if err != nil {
			logit(fmt.Sprintf("TRAP areaMismatch: Area TLV error: %s", err))
			return rundis
		}

		matched := false
		for _, addr := range addrs {
			if bytes.Equal(GlbAreaID, addr) {
				matched = true
				break
			}
		}
		if !matched {
			logit(fmt.Sprintf("TRAP areaMismatch: no matching areas"))
			return rundis
		}
	}

	// ----------------
	// Update Adjacency
	// ----------------
	debug(DbgFAdj, "%s: Updating adjacency for %s", link, pdu.src)

	var snpa [clns.SNPALen]byte
	copy(snpa[:], pdu.src)

	var srcid [clns.SysIDLen]byte
	off := clns.HdrCLNSSize + clns.HdrIIHLANSrcID
	copy(srcid[:], pdu.payload[off:off+clns.SysIDLen])

	a, ok := link.snpaMap[snpa]
	if !ok {
		// Create new adjacency
		a := NewAdj(link, snpa, srcid, pdu.payload, pdu.tlvs)
		link.snpaMap[snpa] = a
		link.srcidMap[srcid] = a
		// If the adjacency state is Up then we want to rerun DIS election
		rundis = a.State == AdjStateUp
	} else if a.sysid != srcid {
		// If the system ID changed ignore and let timeout.
		rundis = false
	} else {
		rundis = a.Update(pdu.payload, pdu.tlvs)
	}
	return rundis
}

//
// UpdateAdjState updates the adj state according to the TLV found in the IIH
//
func (link *LinkLAN) IsAdjStateUP(a *Adj, tlvs map[tlv.Type][]tlv.Data) error {
	// Walk neighbor TLVs if we see ourselves mark adjacency Up.
	for _, ntlv := range tlvs[tlv.TypeISNeighbors] {
		addrs, err := ntlv.ISNeighborsValue()
		if err != nil {
			logger.Printf("ERROR: processing IS Neighbors TLV from %s: %v", a, err)
			return err
		}
		for _, snpa := range addrs {
			if bytes.Equal(snpa, link.circuit.getOurSNPA()) {
				a.State = AdjStateUp
				break
			}
		}
		if a.State == AdjStateUp {
			break
		}
	}
	return nil
}

// ------------
// DIS election
// ------------

//
// disFindBest - ISO10589: 8.4.5
//
// Locking: called with adjdb locked
//
func (link *LinkLAN) disFindBest() (bool, *Adj) {
	electPri := link.priority
	electID := GlbSystemID
	var elect *Adj
	count := 0
	for _, a := range link.srcidMap {
		if a.State != AdjStateUp {
			debug(DbgFDIS, "%s skipping non-up adj %s", link, a)
			continue
		}
		count++
		if a.priority > electPri {
			debug(DbgFDIS, "%s adj %s better priority %d", link, a, a.priority)
			elect = a
			electPri = a.priority
			electID = a.sysid[:]
		} else if a.priority == electPri {
			debug(DbgFDIS, "%s adj %s same priority %d", link, a, a.priority)
			if bytes.Compare(a.sysid[:], electID) > 0 {
				elect = a
				electPri = a.priority
				electID = a.sysid[:]
			}
		} else {
			debug(DbgFDIS, "%s adj %s worse priority %d", link, a, a.priority)
		}
	}
	if count == 0 {
		debug(DbgFDIS, "%s no adj, no dis", link)
		// No adjacencies, no DIS
		return false, nil
	}
	return elect == nil, elect
}

func (link *LinkLAN) disSelfElect() {
	// Always let the update process know.
	link.updb.SetDIS(link.lclCircID, true)

	if link.disElected {
		return
	}
	link.disElected = true

	// XXX Start the CNSP timer.
}

func (link *LinkLAN) disSelfResign() {
	// Always let the update process know.
	link.updb.SetDIS(link.lclCircID, false)

	if !link.disElected {
		return
	}
	link.disElected = false

	// XXX Stop CNSP timer.
}

func (link *LinkLAN) disElect() {
	debug(DbgFDIS, "Running DIS election on %s", link)

	var newLANID clns.NodeID
	oldLANID := link.lanID

	electUs, electOther := link.disFindBest()
	if electUs {
		debug(DbgFDIS, "%s electUS", link)
		newLANID = link.ourlanID
	} else if electOther != nil {
		debug(DbgFDIS, "%s electOther %s", link, electOther)
		newLANID = electOther.lanID
	}

	if oldLANID == newLANID {
		debug(DbgFDIS, "Same DIS elected: %s", newLANID)
		return
	}

	debug(DbgFDIS, "DIS change: old %s new %s", oldLANID, newLANID)

	if !electUs {
		link.disSelfResign()
		if electOther == nil {
			// XXX No DIS -- maybe put a zero here?
			link.lanID = link.ourlanID
		} else {
			link.lanID = newLANID
		}
	} else {
		link.disSelfElect()
	}
}
