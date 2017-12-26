package main

import (
	"bytes"
	"fmt"
	"github.com/choppsv1/goisis/clns"
	"github.com/choppsv1/goisis/ether"
	"github.com/choppsv1/goisis/pkt"
	"github.com/choppsv1/goisis/tlv"
	"net"
	"syscall"
)

// ourSNPA keeps track of all of our SNPA to check for looped back frames
var ourSNPA = make(map[ether.MAC]bool)

//
// LANLink is a structure holding information on a IS-IS LAN link.
//
type LANLink struct {
	*CircuitBase
	levlink [2]*LANLevelLink
}

func (link *LANLink) String() string {
	return fmt.Sprintf("LANLink(%s)", link.LinkCommon)
}

//
// GetOurSNPA returns the SNPA for this link
//
func (link *LANLink) getOurSNPA() net.HardwareAddr {
	return link.LinkCommon.intf.HardwareAddr
}

//
// NewLANLink creates a LAN link for a given IS-IS level.
//
func NewLANLink(ifname string, inpkt chan<- *RecvPDU, quit chan bool, levelf clns.LevelFlag) (*LANLink, error) {
	var err error

	link := &LANLink{}

	link.LinkCommon, err = NewCircuitBase(link, ifname, inpkt, quit)
	if err != nil {
		return nil, err
	}

	// Record our SNPA in the map of our SNPA
	ourSNPA[ether.MACKey(link.LinkCommon.intf.HardwareAddr)] = true

	for i := uint(0); i < 2; i++ {
		if (levelf & (1 << i)) != 0 {
			link.levlink[i] = NewLANLevelLink(link, clns.LIndex(i), quit)
		}
	}

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

//
// OpenPDU returns a frame buffer sized to the MTU of the interface (including
// the L2 frame header) after initializing the CLNS header fields.
//
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

//
// ClosePDU finalizes the PDU length fields given endp "pointer"
//
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

// FrameToPDU is called to validate the frame per link type and return the
// pdu payload. This will be called in the context of the packet read loop so be fast.
func (link *LANLink) FrameToPDU(frame []byte, from syscall.Sockaddr) *RecvPDU {
	var err error

	eframe := ether.Frame(frame)

	pdu := &RecvPDU{
		dst: eframe.GetDst(),
		src: eframe.GetSrc(),
	}

	debug(DbgFPkt, " <- len %d from link %s to %s from %s llclen %d\n",
		len(frame), link.intf.Name, pdu.dst, pdu.src, eframe.GetTypeLen())

	pdu.payload, err = eframe.ValidateFrame(ourSNPA)
	if err != nil {
		if err == ether.ErrOurFrame(true) {
			debug(DbgFPkt, "Dropping our own frame")
		} else {
			debug(DbgFPkt, "Dropping frame due to error: %s", err)
		}
		return nil
	}
	level, err := pdu.pdutype.GetPDULevel()
	if err != nil {
		debug(DbgFPkt, "Dropping frame due to error: %s", err)
		return nil
	}

	pdu.link = link.levlink[level-1]
	if pdu.link == nil {
		debug(DbgFPkt, "Dropping frame as L%s not enabled on %s", level, link)
		return nil
	}

	// Check for expected ether dst (correct mcast or us)
	if !bytes.Equal(pdu.dst, clns.AllLxIS[level-1]) {
		if !bytes.Equal(pdu.dst, link.getOurSNPA()) {

			logger.Printf("Dropping IS-IS frame to non-IS-IS address, exciting extensions in use!?")
			return nil
		}
	}

	if pdu.pdutype, err = clns.GetPDUType(pdu.payload); err != nil {
		logger.Printf("Dropping IS-IS frame due to error: %s", err)
		return nil
	}

	// XXX sanity check from == src?

	return pdu
}
