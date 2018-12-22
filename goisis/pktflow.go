//
// -*- coding: utf-8 -*-
//
// December 28 2017, Christian E. Hopps <chopps@gmail.com>
//
// func readPackets():
//
// (per-link) hello process <- +-+
//                             |D|  <-- FrameToPDU <- readPackets (circuit 1 go rtn)
//  LSP                        |s|   ...
// (per-lvl) Update Process <- |p|  <-- FrameToPDU <- readPackets (circuit N go rtn)
//                             |c|
//     (per-link) flood rtn <- |h|
//  SNP                        +-+
//
package main

import (
	"bytes"
	"github.com/choppsv1/goisis/clns"
	"github.com/choppsv1/goisis/ether"
	. "github.com/choppsv1/goisis/logging" // nolint
	"github.com/choppsv1/goisis/tlv"
	"io"
	"syscall"
)

// readPackets is a go routine to read packets from link and writes to a channel
// after doing some basic validation and baking of the frame into a PDU.
func (c *CircuitLAN) readPackets() {
	Debug(DbgFPkt, "Starting to read packets on %s\n", c)
	for {
		pkt, from, err := c.sock.ReadPacket()
		if err != nil {
			if err == io.EOF {
				Debug(DbgFPkt, "EOF reading from %s, will stop reading from link\n", c)
				return
			}
			Debug(DbgFPkt, "Error reading from link %s: %s\n", c.intf.Name, err)
			continue
		}
		// Debug(DbgFPkt, "Read packet on %s len(%d)\n", c.link, len(frame.pkt))

		// Do Frame Validation and get PDU.
		pdu := c.FrameToPDU(pkt, from)
		if pdu == nil {
			continue
		}

		// Receive IIH inside the circuit's go routine in parallel.
		switch pdu.pdutype {
		case clns.PDUTypeIIHLANL1, clns.PDUTypeIIHLANL2, clns.PDUTypeIIHP2P:
			c.RecvHello(pdu)
		case clns.PDUTypeLSPL1, clns.PDUTypeLSPL2:
			c.updb[pdu.li].InputLSP(c, pdu.payload, pdu.pdutype, pdu.tlvs)
		case clns.PDUTypeCSNPL1, clns.PDUTypeCSNPL2, clns.PDUTypePSNPL1, clns.PDUTypePSNPL2:
			c.updb[pdu.li].InputSNP(c, pdu.payload, pdu.pdutype, pdu.tlvs)
		default:
			Debug(DbgFPkt, "Unknown PDU type %s on %s\n", pdu.pdutype, c.intf.Name)
		}

	}
}

// writePackets is a go routine to read packets from a channel and output to link.
func (c *CircuitLAN) writePackets() {
	Debug(DbgFPkt, "Starting to write packets on %s\n", c)
	for {
		select {
		case pkt := <-c.outpkt:
			addr := ether.Frame(pkt).GetDst()
			Debug(DbgFPkt, "[socket] <- len %d from link channel %s to %s\n",
				len(pkt),
				c.intf.Name,
				addr)
			n, err := c.sock.WritePacket(pkt, addr)
			if err != nil {
				Debug(DbgFPkt, "Error writing packet to %s: %s\n",
					c.intf.Name, err)
			} else {
				Debug(DbgFPkt, "Wrote packet len %d/%d to %s\n",
					len(pkt), n, c.intf.Name)
			}
		case <-c.quit:
			Debug(DbgFPkt, "Got quit signal for %s, will stop writing to link\n", c)
			return
		}
	}
}

// FrameToPDU is called to validate the frame per circuit type and return the
// pdu payload. This will be called in the context of the packet read loop so be fast.
func (c *CircuitLAN) FrameToPDU(frame []byte, from syscall.Sockaddr) *RecvPDU {
	var err error

	eframe := ether.Frame(frame)

	pdu := &RecvPDU{
		dst: eframe.GetDst(),
		src: eframe.GetSrc(),
	}

	Debug(DbgFPkt, " <- len %d from circuit %s to %s from %s llclen %d\n",
		len(frame), c.intf.Name, pdu.dst, pdu.src, eframe.GetTypeLen())

	var llc []byte
	pdu.payload, llc, err = eframe.ValidateLLCFrame(ourSNPA)
	if err != nil {
		if err == ether.ErrOurFrame(true) {
			Debug(DbgFPkt, "Dropping our own frame")
		} else {
			Debug(DbgFPkt, "Dropping frame due to: %s", err)
		}
		return nil
	}

	pdu.payload, pdu.pdutype, err = clns.ValidatePDU(llc, pdu.payload, GlbISType, c.lf)
	if err != nil {
		Debug(DbgFPkt, "Dropping IS-IS frame due to: %s", err)
		return nil
	}

	l, err := pdu.pdutype.GetPDULevel()
	if err != nil {
		Debug(DbgFPkt, "Dropping frame due to: %s", err)
		return nil
	}
	pdu.l = l

	// Check for expected ether dst (correct mcast or us)
	if !c.lf.IsLevelEnabled(l) {
		Debug(DbgFPkt, "Dropping %s frame not enabled on %s", l, c)
		return nil
	}

	pdu.link = c.levlink[l-1]

	if !bytes.Equal(pdu.dst, clns.AllLxIS[l-1]) {
		if !bytes.Equal(pdu.dst, c.getOurSNPA()) {

			Debug(DbgFPkt, "Dropping IS-IS frame to non-IS-IS address, exciting extensions in use!?")
			return nil
		}
	}

	tlvp := tlv.Data(pdu.payload[clns.PDUTLVOffMap[pdu.pdutype]:])
	pdu.tlvs, err = tlvp.ParseTLV()
	if err != nil {
		Debug(DbgFPkt, "Dropping frame on %s due to TLV error %s", c, err)
		return nil
	}

	// XXX sanity check from == src?

	return pdu
}
