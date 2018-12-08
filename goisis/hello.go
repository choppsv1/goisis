// -*- coding: utf-8 -*-
//
// Copyright (c) 2018, Christian Hopps
// All Rights Reserved.
//
// Implement the IS-IS hello process
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

// =========
// Adjacency
// =========

//
// AdjState represents the state of the IS-IS adjcency
//
type AdjState uint8

//
// AdjState constants for the state of the IS-IS adjcency
//
const (
	AdjStateDown AdjState = iota
	AdjStateInit
	AdjStateUp
)

var stateStrings = map[AdjState]string{
	AdjStateDown: "AdjStateUp",
	AdjStateInit: "AdjStateInit",
	AdjStateUp:   "AdjStateUp",
}

func (s AdjState) String() string {
	ss, ok := stateStrings[s]
	if !ok {
		return fmt.Sprintf("Unknown AdjState(%d)", s)
	}
	return ss
}

//
// Adj represents an IS-IS adjacency
//
type Adj struct {
	// Immutable.
	link  Link
	lf    clns.LevelFlag //  need to change this to LevelFlag for p2p
	sysid clns.SystemID
	snpa  clns.SNPA // XXX need to conditionalize this for P2P.

	// Mutable.
	State     AdjState
	areas     [][]byte
	holdTimer *time.Timer

	// LAN state
	lanID    clns.NodeID
	priority uint8
}

func (a *Adj) String() string {
	return fmt.Sprintf("Adj(%s,%s,%s)", clns.ISOString(a.sysid[:], false), a.link, a.State)
}

// =============
// Hello Process
// =============

// StartHelloProcess starts a go routine to send and receive hellos, manage
// adjacencies and elect DIS on LANs
func StartHelloProcess(link *LinkLAN, interval uint, quit <-chan bool) {
	debug(DbgFPkt, "Sending hellos on %s with interval %d", link, interval)
	ival := time.Second * time.Duration(interval)
	ticker := time.NewTicker(ival) // XXX replace with jittered timer.
	go helloProcess(ticker.C, link, quit)
}

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
			debug(DbgFAdj, "Adj for %s on %s expiring.", srcid, link)
			a := link.srcidMap[srcid]
			if a == nil {
				debug(DbgFAdj, "Adj for %s on %s is already gone.", srcid, link)
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
			debug(DbgFAdj, "Ticker timer fires %s", link)
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

// hasUpAdj returns true if the DB contains any Up adjacencies
// hasUpAdjSNPA returns true if the DB contains any Up adjacencies

// getAdjSNPA returns an list of SNPA for all non-DOWN adjacencies
func (link *LinkLAN) getKnownSNPA() []net.HardwareAddr {
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

	endp, err = tlv.AddAdjSNPA(endp, link.getKnownSNPA())
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

// Update updates the adjacency with the information from the IIH, returns true
// if DIS election should be re-run.
func (a *Adj) UpdateAdj(pdu *RecvPDU) bool {
	rundis := false
	iihp := pdu.payload[clns.HdrCLNSSize:]

	if a.lf.IsLevelEnabled(1) {
		// Update Areas
		areas, err := pdu.tlvs[tlv.TypeAreaAddrs][0].AreaAddrsValue()
		if err != nil {
			logger.Printf("ERROR: processing Area Address TLV from %s: %s", a, err)
			return true
		}
		a.areas = areas
	}

	if a.holdTimer != nil && !a.holdTimer.Stop() {
		debug(DbgFAdj, "%s failed to stop hold timer in time, letting expire", a)
		return false
	}

	oldstate := a.State
	a.State = AdjStateInit

	if a.link.IsP2P() {
		// XXX writeme
	} else {
		iih := pdu.payload[clns.HdrCLNSSize:]
		copy(a.lanID[:], iih[clns.HdrIIHLANLANID:])

		ppri := iihp[clns.HdrIIHLANPriority]
		if ppri != a.priority {
			a.priority = ppri
			rundis = true
		}

		ourSNPA := a.link.GetOurSNPA()
	forloop:
		// Walk neighbor TLVs if we see ourselves mark adjacency Up.
		for _, ntlv := range pdu.tlvs[tlv.TypeISNeighbors] {
			addrs, err := ntlv.ISNeighborsValue()
			if err != nil {
				logger.Printf("ERROR: processing IS Neighbors TLV from %s: %v", a, err)
				break
			}
			for _, snpa := range addrs {
				if bytes.Equal(snpa, ourSNPA) {
					a.State = AdjStateUp
					break forloop
				}
			}
		}
	}

	if a.State != oldstate {
		if a.State == AdjStateUp {
			rundis = true
			logger.Printf("TRAP: AdjacencyStateChange: Up: %s", a)
		} else if oldstate == AdjStateUp {
			rundis = true
			logger.Printf("TRAP: AdjacencyStateChange: Down: %s", a)
		}
		debug(DbgFAdj, "New state %s for %s", a.State, a)
	}

	// Restart the hold timer.
	holdtime := pkt.GetUInt16(iihp[clns.HdrIIHHoldTime:])
	if a.holdTimer == nil {
		a.holdTimer = time.AfterFunc(time.Second*time.Duration(holdtime),
			func() {
				sysid := a.sysid
				a.link.ExpireAdj(sysid)
			})
	} else {
		a.holdTimer.Reset(time.Second * time.Duration(holdtime))
	}

	debug(DbgFAdj, "%s: Updated adjacency %s for SNPA %s from %s to %s rundis %v",
		a.link, a.sysid, a.snpa, oldstate, a.State, rundis)

	return rundis
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
		// ISO10589 8.4.2.2: Receipt of level 1 IIH PDUs

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

		// ISO10589 8.4.2.2.a: Look for our area in TLV.
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

	a, ok := link.snpaMap[clns.HWToSNPA(pdu.src)]
	if !ok {
		a = &Adj{
			link:  pdu.link,
			lf:    pdu.l.ToFlag(),
			sysid: clns.GetSrcID(pdu.payload),
			snpa:  clns.HWToSNPA(pdu.src),
		}
		link.snpaMap[a.snpa] = a
		link.srcidMap[a.sysid] = a
	}

	srcid := clns.GetSrcID(pdu.payload)
	// ISO10589 8.4.2.4: Make sure snpa, srcid and nbrSysType same
	// XXX the standard is fuzzy here, is nbrSysType supposed to
	// trace CircType from the IIH or the value it talks about just
	// above which is based on the IIH level.
	if a.sysid != srcid {
		// If the system ID changed ignore and let timeout.
		rundis = false
	} else {
		rundis = a.UpdateAdj(pdu)
	}
	return rundis
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
	debug(DbgFDIS, "DIS change: elect %v", link)
	link.updb.SetDIS(link.lclCircID, true)
	debug(DbgFDIS, "DIS change: elect %v done", link)

	if link.disElected {
		return
	}
	link.disElected = true

	// XXX Start the CNSP timer.
}

func (link *LinkLAN) disSelfResign() {
	// Always let the update process know.
	debug(DbgFDIS, "DIS change: resign %v", link)
	link.updb.SetDIS(link.lclCircID, false)
	debug(DbgFDIS, "DIS change: resign %v done", link)

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
