package main

import (
	"bytes"
	"fmt"
	"github.com/choppsv1/goisis/clns"
	"github.com/choppsv1/goisis/ether"
	"github.com/choppsv1/goisis/pkt"
	"github.com/choppsv1/goisis/tlv"
	"net"
)

// lanLinkCircuitIDs is used to allocate circuit IDs
var lanLinkCircuitIDs = [2]byte{0, 0}

// ourSNPA keeps track of all of our SNPA to check for looped back frames
var ourSNPA = make(map[ether.MAC]bool)

// ---------------------------------------------------------------
// LANLink is a structure holding information on a IS-IS LAN link.
// ---------------------------------------------------------------
type LANLink struct {
	*LinkCommon
	level     int
	lindex    int //  level - 1 for array indexing
	helloInt  int
	holdMult  int
	lclCircID uint8
	lanID     [clns.LANIDLen]byte
	adjdb     *AdjDB
}

func (link *LANLink) String() string {
	return fmt.Sprintf("LANLink(%s level %d)", link.LinkCommon, link.level)
}

// -----------------------------------------
// GetOurSNPA returns the SNPA for this link
// -----------------------------------------
func (link *LANLink) GetOurSNPA() net.HardwareAddr {
	return link.LinkCommon.intf.HardwareAddr
}

// ------------------------------------------------------
// NewLANLink creates a LAN link for a given IS-IS level.
// ------------------------------------------------------
func NewLANLink(ifname string, inpkt chan<- *RecvFrame, quit chan bool, level int) (*LANLink, error) {
	var err error

	link := &LANLink{
		level:    level,
		lindex:   level - 1,
		helloInt: clns.DefHelloInt,
		holdMult: clns.DefHelloMult,
	}

	link.LinkCommon, err = NewLink(link, ifname, inpkt, quit)
	if err != nil {
		return nil, err
	}

	link.adjdb = NewAdjDB(link, level)

	lanLinkCircuitIDs[link.lindex]++
	link.lclCircID = lanLinkCircuitIDs[link.lindex]
	copy(link.lanID[:], GlbSystemID)
	link.lanID[clns.SysIDLen] = link.lclCircID

	// Record our SNPA in the map of our SNPA
	ourSNPA[ether.MACKey(link.LinkCommon.intf.HardwareAddr)] = true

	go SendLANHellos(link, link.helloInt, quit)

	return link, nil
}

// clnsTemplate are the static values we use in the CLNS header.
var clnsTemplate = []uint8{
	clns.LLCSSAP,
	clns.LLCDSAP,
	clns.LLCControl,
	clns.IDRPISIS,
	0, // Header Length
	clns.Version,
	clns.SysIDLen,
	0, // PDU Type
	clns.Version2,
	0,            // Reserved
	clns.MaxArea, // Max Area
}

// ---------------------------------------------------------------------------
// OpenPDU returns a frame buffer sized to the MTU of the interface (including
// the L2 frame header) after initializing the CLNS header fields.
// ---------------------------------------------------------------------------
func (link *LANLink) OpenPDU(pdutype clns.PDUType, dst net.HardwareAddr) (ether.Frame, []byte, []byte) {
	etherp := make([]byte, link.intf.MTU+14)

	copy(etherp[ether.HdrEthDest:], dst)
	copy(etherp[ether.HdrEthSrc:], link.intf.HardwareAddr)
	clnsp := etherp[ether.HdrEthSize:]
	copy(clnsp, clnsTemplate)
	clnsp[clns.HdrCLNSPDUType] = uint8(pdutype)
	clnsp[clns.HdrCLNSLen] = clns.HdrLenMap[pdutype]
	return etherp, clnsp, clnsp[clns.HdrCLNSSize:]
}

// -------------------------------------------------------------
// ClosePDU finalizes the PDU length fields given endp "pointer"
// -------------------------------------------------------------
func (link *LANLink) ClosePDU(etherp ether.Frame, endp []byte) error {
	ethlen := tlv.GetOffset([]byte(etherp), endp)
	payload := ethlen - ether.HdrEthSize
	pdulen := payload - clns.HdrLLCSize
	pdutype := etherp[ether.HdrEthSize+clns.HdrCLNSPDUType]
	lenoff := clns.PDULenOffMap[clns.PDUType(pdutype)]

	// Calculate the packet size and fill in various places
	lenoff = ether.HdrEthSize + lenoff
	pkt.PutUInt16(etherp[lenoff:], uint16(pdulen))

	etherp = etherp[0 : payload+ether.HdrEthSize]
	etherp.SetTypeLen(payload)

	debug(DbgFPkt, "Closing PDU with pdulen %d payload %d framelen %d",
		pdulen, payload, len(etherp))
	return nil
}

// =================
// Packet Processing
// =================

// ProcessPacket is called with a frame received on this link. Currently all
// received packets are handled serially in the order they arrive (using a
// single go routine). This could be changed in the future don't rely on it.
func (link *LANLink) ProcessPacket(frame *RecvFrame) error {
	// Validate ethernet values.
	// var src, dst [clns.SNPALen]byte
	var pdutype clns.PDUType

	payload, err := ether.Frame(frame.pkt).ValidateFrame(ourSNPA)
	if err != nil {
		if err == ether.ErrOurFrame(true) {
			debug(DbgFPkt, "Dropping our own frame")
			return nil
		}
		return err
	}
	// No error but should drop.
	if payload == nil {
		return nil
	}

	// Check for expected ether dst (correct mcast or us)
	dst := ether.Frame(frame.pkt).GetDst()
	if !bytes.Equal(dst, clns.AllLxIS[link.lindex]) {
		if !bytes.Equal(dst, link.GetOurSNPA()) {
			logger.Printf("Dropping IS-IS frame to non-IS-IS address, exciting extensions?")
			return nil
		}
	}

	payload, err = clns.ValidatePacket(payload)
	if err != nil {
		return err
	}

	pdutype, err = clns.GetPDUType(payload)
	if err != nil {
		return err
	}
	level, ok := clns.PDULevelMap[pdutype]
	if !ok {
		logger.Printf("WARNING: ignoring unexpected PDU type %s on %s", pdutype, link)
		return nil
	}

	tlvp := tlv.Data(payload[clns.PDUTLVOffMap[pdutype]:])
	tlvs, err := tlvp.ParseTLV()
	if err != nil {
		return err
	}

	switch pdutype {
	case clns.PDUTypeIIHLANL1:
		return RecvLANHello(link, frame, payload, level, tlvs)
	case clns.PDUTypeIIHLANL2:
		return RecvLANHello(link, frame, payload, level, tlvs)
	case clns.PDUTypeLSPL1:
		debug(DbgFPkt, "INFO: ignoring LSPL1 on %s for now", link)
		return nil
	case clns.PDUTypeLSPL2:
		debug(DbgFPkt, "INFO: ignoring LSPL2 on %s for now", link)
		return nil
	case clns.PDUTypeCSNPL1:
		debug(DbgFPkt, "INFO: ignoring CSNPL1 on %s for now", link)
		return nil
	case clns.PDUTypeCSNPL2:
		debug(DbgFPkt, "INFO: ignoring CSNPL2 on %s for now", link)
		return nil
	case clns.PDUTypePSNPL1:
		debug(DbgFPkt, "INFO: ignoring PSNPL1 on %s for now", link)
		return nil
	case clns.PDUTypePSNPL2:
		debug(DbgFPkt, "INFO: ignoring PSNPL2 on %s for now", link)
		return nil
	default:
		logger.Printf("WARNING: ignoring unexpected PDU type %s on %s", pdutype, link)
		return nil
	}
}

// ===================
// Adjacency Functions
// ===================

// ----------------------------------------------------------------------------
// DISInfoChanged is called when something has happened to require rerunning of
// DIS election on this LAN.
// ----------------------------------------------------------------------------
func (link *LANLink) DISInfoChanged(level int) {
	// XXX
}

// --------------------------------------------------------------------------
// UpdateAdjState updates the adj state according to the TLV found in the IIH
// --------------------------------------------------------------------------
func (link *LANLink) UpdateAdjState(a *Adj, tlvs map[tlv.Type][]tlv.Data) error {
	// Walk neighbor TLVs if we see ourselves mark adjacency Up.
	for _, ntlv := range tlvs[tlv.TypeISNeighbors] {
		addrs, err := ntlv.ISNeighborsValue()
		if err != nil {
			logger.Printf("ERROR: processing IS Neighbors TLV from %s: %s", a, err)
			return err
		}
		for _, snpa := range addrs {
			if bytes.Equal(snpa, link.GetOurSNPA()) {
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
