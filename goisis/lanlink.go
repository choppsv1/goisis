package main

import (
	"fmt"
	"github.com/choppsv1/goisis/clns"
	"github.com/choppsv1/goisis/ether"
	"github.com/choppsv1/goisis/pkt"
	"github.com/choppsv1/goisis/tlv"
	"net"
)

var lanLinkCircuitIDs = [2]byte{0, 0}

var ourSNPA = make(map[ether.MAC]bool)

// LANLink is a structure holding information on a IS-IS LAN link.
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

// NewLANLink creates a LAN link for a given IS-IS level.
func NewLANLink(ifname string, inpkt chan<- *Frame, quit chan bool, level int) (*LANLink, error) {
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
	copy(link.lanID[:], SystemID)
	link.lanID[clns.SysIDLen] = link.lclCircID

	// Record our SNPA in the map of our SNPA
	ourSNPA[ether.MACKey(link.LinkCommon.intf.HardwareAddr)] = true

	go sendLANHellos(link, link.helloInt, quit)

	return link, nil
}

// OpenPDU returns a frame buffer sized to the MTU of the interface (including
// the L2 frame header) after initializing the CLNS header fields.
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

// ClosePDU finalizes the PDU length fields given endp "pointer"
func (link *LANLink) ClosePDU(etherp ether.Frame, endp []byte) error {
	ethlen := tlv.GetPacketOffset([]byte(etherp), endp)
	payload := ethlen - ether.HdrEthSize
	pdulen := payload - clns.HdrLLCSize
	pdutype := etherp[ether.HdrEthSize+clns.HdrCLNSPDUType]
	lenoff := clns.PDULenOffMap[clns.PDUType(pdutype)]

	// Calculate the packet size and fill in various places
	lenoff = ether.HdrEthSize + lenoff
	pkt.PutUInt16(etherp[lenoff:], uint16(pdulen))

	etherp = etherp[0 : payload+ether.HdrEthSize]
	etherp.SetEtherTypeLen(payload)

	debug.Printf("Closing PDU with pdulen %d payload %d framelen %d",
		pdulen, payload, len(etherp))
	return nil
}

// DISInfoChanged is called when something has happened to require rerunning of
// DIS election on this LAN.
func (link *LANLink) DISInfoChanged(level int) {
	// XXX
}

// ErrIIH is a general error in IIH packet processing
type ErrIIH string

func (e ErrIIH) Error() string {
	return fmt.Sprintf("ErrIIH: %s", string(e))
}

func (link *LANLink) processIIH(frame *Frame, payload []byte, level int, tlvs map[tlv.Type][]tlv.Data) error {
	if level == 1 {
		// Expect 1 and only 1 Area TLV
		atlv := tlvs[tlv.TypeAreaAddrs]
		if len(atlv) != 1 {
			return ErrIIH(fmt.Sprintf("INFO: areaMismatch: Incorrect area TLV count: %d", len(atlv)))
		}
		// XXX Verify at least 1 area matches
		// return ErrIIH(fmt.Sprintf("TRAP areaMismatch: no matching areas"))
	}
	// _ == rundis
	eframe := ether.Frame(frame.pkt)
	link.adjdb.UpdateAdj(payload, tlvs, eframe.GetEtherSrc())
	return nil
}

// ProcessPacket is called with a frame received on this link. Currently all
// received packets are handled serially in the order they arrive (using a
// single go routine). This could be changed in the future don't rely on it.
func (link *LANLink) ProcessPacket(frame *Frame) error {
	// Validate ethernet values.
	// var src, dst [clns.SNPALen]byte
	var pdutype clns.PDUType

	payload, err := ether.Frame(frame.pkt).ValidateFrame(ourSNPA)
	if err != nil {
		if err == ether.ErrOurFrame(true) {
			debug.Printf("Dropping our own frame")
			return nil
		}
		return err
	}
	// No error but should drop.
	if payload == nil {
		return nil
	}

	// XXX check for source being us.
	// copy(src[:], frame.pkt.GetEtherSrc())

	// XXX check for expected dst (mcast or us)
	// copy(dst[:], frame.pkt.GetEtherDest())

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

	debug.Printf("INFO: paylen len before parse %d", len(payload))
	tlvp := tlv.Data(payload[clns.PDUTLVOffMap[pdutype]:])
	tlvs, err := tlvp.ParseTLV()
	if err != nil {
		return err
	}

	switch pdutype {
	case clns.PDUTypeIIHLANL1:
		return link.processIIH(frame, payload, level, tlvs)
	case clns.PDUTypeIIHLANL2:
		return link.processIIH(frame, payload, level, tlvs)
	case clns.PDUTypeLSPL1:
		logger.Printf("INFO: ignoring LSPL1 on %s for now", link)
		return nil
	case clns.PDUTypeLSPL2:
		logger.Printf("INFO: ignoring LSPL2 on %s for now", link)
		return nil
	case clns.PDUTypeCSNPL1:
		logger.Printf("INFO: ignoring CSNPL1 on %s for now", link)
		return nil
	case clns.PDUTypeCSNPL2:
		logger.Printf("INFO: ignoring CSNPL2 on %s for now", link)
		return nil
	case clns.PDUTypePSNPL1:
		logger.Printf("INFO: ignoring PSNPL1 on %s for now", link)
		return nil
	case clns.PDUTypePSNPL2:
		logger.Printf("INFO: ignoring PSNPL2 on %s for now", link)
		return nil
	default:
		logger.Printf("WARNING: ignoring unexpected PDU type %s on %s", pdutype, link)
		return nil
	}
}
