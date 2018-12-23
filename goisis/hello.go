// -*- coding: utf-8 -*-
//
// Copyright (c) 2018, Christian Hopps
// All Rights Reserved.
//

// Implement the IS-IS hello process
package main

import (
	"bytes"
	"fmt"
	"github.com/choppsv1/goisis/clns"
	. "github.com/choppsv1/goisis/logging" // nolint
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
	AdjStateDown: "AdjStateDown",
	AdjStateInit: "AdjStateInit",
	AdjStateUp:   "AdjStateUp",
}

var marshalStrings = map[AdjState]string{
	AdjStateDown: "down",
	AdjStateInit: "init",
	AdjStateUp:   "up",
}

func (s AdjState) String() string {
	ss, ok := stateStrings[s]
	if !ok {
		return fmt.Sprintf("Unknown AdjState(%d)", s)
	}
	return ss
}

func (s AdjState) MarshalText() ([]byte, error) {
	ss, ok := marshalStrings[s]
	if !ok {
		return nil, fmt.Errorf("Bogus Adjacency State value %d", s)
	}
	return []byte(ss), nil
}

//
// Adj represents an IS-IS adjacency
//
type Adj struct {
	// Immutable.
	link  Link
	usage clns.LevelFlag
	sysid clns.SystemID
	snpa  clns.SNPA

	// Mutable.
	ctype     clns.LevelFlag
	state     AdjState
	areas     [][]byte
	holdTimer *time.Timer

	// LAN state
	lanID    clns.NodeID
	priority uint8
}

func (a *Adj) String() string {
	return fmt.Sprintf("Adj(%s,%s,%s)", clns.ISOString(a.sysid[:], false), a.link, a.state)
}

type getAdj struct {
	c     chan<- interface{}
	forPN bool
}

// =============
// Hello Process
// =============

// StartHelloProcess starts a go routine to send and receive hellos, manage
// adjacencies and elect DIS on LANs
func StartHelloProcess(link *LinkLAN, quit <-chan bool) {
	Debug(DbgFPkt, "Sending hellos on %s with interval %d", link, link.helloInt)
	ival := time.Second * time.Duration(link.helloInt)
	link.ticker = time.NewTicker(ival) // XXX replace with jittered timer.

	go helloProcess(link, quit)
}

// sendLANHellos is a go routine that sends hellos based using a ticker
// It also processes DIS update events.
// nolint: gocyclo
func helloProcess(link *LinkLAN, quit <-chan bool) {
	disWaiting := true
	wasWaiting := true

	if err := sendLANHello(link); err != nil {
		Trap("%s: error sending LAN hello: %s", link, err)
	}

	for {

		var rundis bool
		select {
		case <-quit:
			Debug(DbgFPkt, "Stop sending IIH on %s", link)
			return
		case ga := <-link.getAdjC:
			link.getAdjacencies(ga)
		case pdu := <-link.iihpkt:
			rundis = pdu.link.RecvHello(pdu)
		case srcid := <-link.expireC:
			Debug(DbgFAdj, "Adj for %s on %s expiring.", srcid, link)
			a := link.srcidMap[srcid]
			if a == nil {
				Debug(DbgFAdj, "Adj for %s on %s is already gone.", srcid, link)
				break
			}
			// If the adjacency was up then we need to rerun DIS election.
			rundis = a.state == AdjStateUp
			delete(link.snpaMap, a.snpa)
			delete(link.srcidMap, a.sysid)
		case <-link.disTimer.C:
			Debug(DbgFDIS, "INFO: DIS timer fires %s", link)
			disWaiting = false
			rundis = true
		case <-link.ticker.C:
			if err := sendLANHello(link); err != nil {
				Trap("%s: error sending LAN hello: %s", link, err)
			}
		}

		if rundis {
			if disWaiting {
				Debug(DbgFDIS, "INFO: Suppress DIS elect on %s", link)
			} else {
				Debug(DbgFDIS, "INFO: DIS info changed on %s", link)
				link.disElect(wasWaiting)
				wasWaiting = false
			}
		}
	}
}

func (link *LinkLAN) getAdjacencies(in getAdj) {
	if !in.forPN {
		Debug(DbgFPkt, "Sending LANID %s on channel", link.lanID)
		in.c <- tlv.AdjInfo{
			Metric: clns.DefExtISMetric,
			Nodeid: link.lanID,
		}
		in.c <- tlv.Done{}
		return
	}
	for _, a := range link.srcidMap {
		if a.state != AdjStateUp {
			continue
		}
		Debug(DbgFPkt, "Sending Up Adj %s on channel", a)
		adj := tlv.AdjInfo{
			Metric: clns.DefExtISMetric,
		}
		copy(adj.Nodeid[:], a.sysid[:])
		in.c <- adj
	}
	in.c <- tlv.Done{}
}

// hasUpAdj returns true if the DB contains any Up adjacencies
// hasUpAdjSNPA returns true if the DB contains any Up adjacencies

// getAdjSNPA returns an list of SNPA for all non-DOWN adjacencies
func (link *LinkLAN) getKnownSNPA() []net.HardwareAddr {
	alist := make([]net.HardwareAddr, 0, len(link.srcidMap))
	for _, a := range link.srcidMap {
		Debug(DbgFPkt, "Sending IIH Add Adj %s", a)
		if a.state != AdjStateDown {
			alist = append(alist, a.snpa[:])
		}
	}
	return alist
}

// nolint: gocyclo
func sendLANHello(link *LinkLAN) error {
	var err error
	var pdutype clns.PDUType

	Debug(DbgFPkt, "Sending IIH on %s", link)

	if link.l == 1 {
		pdutype = clns.PDUTypeIIHLANL1
	} else {
		pdutype = clns.PDUTypeIIHLANL2
	}

	// XXX we want the API to return payload here and later we convert frame
	// in close so that we aren't dependent on ethernet
	etherp, _, iihp, endp := link.circuit.OpenPDU(pdutype, clns.AllLxIS[link.li])
	bt := tlv.NewSingleBufferTrack(endp)

	// ----------
	// IIH Header
	// ----------

	iihp[clns.HdrIIHLANCircType] = uint8(link.l)
	copy(iihp[clns.HdrIIHLANSrcID:], GlbSystemID[:])
	pkt.PutUInt16(iihp[clns.HdrIIHLANHoldTime:],
		uint16(link.helloInt*link.holdMult))
	iihp[clns.HdrIIHLANPriority] = link.priority & 0x7F
	copy(iihp[clns.HdrIIHLANLANID:], link.lanID[:])

	// --------
	// Add TLVs
	// --------

	if link.l == 1 {
		if err = bt.AddAreas(GlbAreaIDs); err != nil {
			Debug(DbgFPkt, "Error adding area TLV: %s", err)
			return err
		}
	}

	if err = bt.AddNLPID(GlbNLPID); err != nil {
		Debug(DbgFPkt, "Error adding NLPID TLV: %s", err)
		return err
	}

	if err = bt.AddIntfAddrs(link.circuit.v4addrs); err != nil {
		return err
	}

	if err = bt.AddIntfAddrs(link.circuit.v6lladdrs); err != nil {
		return err
	}

	if err = bt.AddAdjSNPA(link.getKnownSNPA()); err != nil {
		Debug(DbgFPkt, "Error Adding SNPA: %s", err)
		return err
	}

	if err = bt.Close(); err != nil {
		return err
	}

	endp = bt.EndSpace()

	// Pad to MTU
	for cap(endp) > 1 {
		endp, err = tlv.AddPadding(endp)
		if err != nil {
			Debug(DbgFPkt, "Error adding Padding TLVs: %s", err)
			return err
		}
	}

	// Send the packet
	link.circuit.outpkt <- link.circuit.ClosePDU(etherp, endp)

	return nil
}

// UpdateAdj updates the adjacency with the information from the IIH, returns true
// if DIS election should be re-run.
// nolint: gocyclo
func (a *Adj) UpdateAdj(pdu *RecvPDU) bool {
	rundis := false
	iihp := pdu.payload[clns.HdrCLNSSize:]

	if a.usage.IsLevelEnabled(1) {
		// Update Areas
		areas, err := pdu.tlvs[tlv.TypeAreaAddrs][0].AreaAddrsValue()
		if err != nil {
			Info("ERROR: processing Area Address TLV from %s: %s", a, err)
			return true
		}
		a.areas = areas
	}

	if a.holdTimer != nil && !a.holdTimer.Stop() {
		Debug(DbgFAdj, "%s failed to stop hold timer in time, letting expire", a)
		return false
	}

	oldstate := a.state
	a.state = AdjStateInit

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
				Info("ERROR: processing IS Neighbors TLV from %s: %v", a, err)
				break
			}
			for _, snpa := range addrs {
				if bytes.Equal(snpa, ourSNPA) {
					a.state = AdjStateUp
					break forloop
				}
			}
		}
	}

	if a.state != oldstate {
		if a.state == AdjStateUp {
			rundis = true
			Trap("TRAP: AdjacencyStateChange: Up: %s", a)
		} else if oldstate == AdjStateUp {
			rundis = true
			Trap("TRAP: AdjacencyStateChange: Down: %s", a)
		}
		Debug(DbgFAdj, "New state %s for %s", a.state, a)
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

	Debug(DbgFAdj, "%s: Updated adjacency %s for SNPA %s from %s to %s rundis %v",
		a.link, a.sysid, a.snpa, oldstate, a.state, rundis)

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

// RecvHello receives IIH from on a given LAN link
func (link *LinkLAN) RecvHello(pdu *RecvPDU) bool {
	Debug(DbgFPkt, "IIH: processign from %s", pdu.src)
	var rundis bool

	tlvs := pdu.tlvs

	// ISO10589 8.4.2.1.c auth.

	// For level 1 we must be in the same area.
	if pdu.l == 1 {
		// ISO10589 8.4.2.2: Receipt of level 1 IIH PDUs

		// Expect 1 and only 1 Area TLV
		atlv := tlvs[tlv.TypeAreaAddrs]
		if len(atlv) != 1 {
			Trap("areaMismatch: Incorrect area TLV count: %d", len(atlv))
			return rundis
		}
		addrs, err := atlv[0].AreaAddrsValue()
		if err != nil {
			Trap("areaMismatch: Area TLV error: %s", err)
			return rundis
		}

		// ISO10589 8.4.2.2.a: Look for our area in TLV.
		matched := false
	FOUND:
		for _, addr := range addrs {
			for _, area := range GlbAreaIDs {
				if bytes.Equal(area, addr) {
					matched = true
					break FOUND
				}
			}
		}
		if !matched {
			Trap("TRAP areaMismatch: no matching areas")
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
			ctype: clns.LevelFlag(pdu.payload[clns.HdrCLNSSize+clns.HdrIIHCircType] & 0x3),
			usage: pdu.l.ToFlag(),
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
		if a.state != AdjStateUp {
			Debug(DbgFDIS, "%s skipping non-up adj %s", link, a)
			continue
		}
		count++
		if a.priority > electPri {
			Debug(DbgFDIS, "%s adj %s better priority %d", link, a, a.priority)
			elect = a
			electPri = a.priority
			electID = a.sysid
		} else if a.priority == electPri {
			Debug(DbgFDIS, "%s adj %s same priority %d", link, a, a.priority)
			if bytes.Compare(a.sysid[:], electID[:]) > 0 {
				elect = a
				electPri = a.priority
				electID = a.sysid
			}
		} else {
			Debug(DbgFDIS, "%s adj %s worse priority %d", link, a, a.priority)
		}
	}
	if count == 0 {
		Debug(DbgFDIS, "%s no adj, no dis", link)
		// No adjacencies, no DIS
		return false, nil
	}
	return elect == nil, elect
}

func (link *LinkLAN) disSelfElect() {
	if link.disElected {
		return
	}
	link.disElected = true

	ival := time.Second * time.Duration(link.helloInt) / 3
	link.ticker.Stop()
	link.ticker = time.NewTicker(ival) // XXX replace with jittered timer.
}

func (link *LinkLAN) disSelfResign() {
	if !link.disElected {
		return
	}
	link.disElected = false

	ival := time.Second * time.Duration(link.helloInt)
	link.ticker.Stop()
	link.ticker = time.NewTicker(ival) // XXX replace with jittered timer.
}

func (link *LinkLAN) disElect(firstRun bool) {
	Debug(DbgFDIS, "Running DIS election on %s first time %v", link, firstRun)

	var newLANID clns.NodeID
	var oldLANID clns.NodeID
	if !firstRun {
		oldLANID = link.lanID
	}

	electUs, electOther := link.disFindBest()
	if electUs {
		Debug(DbgFDIS, "%s electUS", link)
		newLANID = link.ourlanID
	} else if electOther != nil {
		if !bytes.Equal(electOther.lanID[:clns.SysIDLen], electOther.sysid[:]) {
			Debug(DbgFDIS, "%s electOther %s Resigns!", link, electOther)
		} else {
			Debug(DbgFDIS, "%s electOther %s", link, electOther)
			newLANID = electOther.lanID
		}
	} else {
		Debug(DbgFDIS, "%s elect None!", link)
	}

	if oldLANID == newLANID {
		Debug(DbgFDIS, "Same DIS elected: %s", newLANID)
		return
	}

	Debug(DbgFDIS, "DIS change: old %s new %s", oldLANID, newLANID)

	// newLANID may be 0s if no-one elected.
	link.lanID = newLANID

	// Always let the update process know.
	link.updb.ChangeDIS(link.circuit, link.lanID[clns.SysIDLen])

	if !electUs {
		link.disSelfResign()
	} else {
		link.disSelfElect()
	}
}
