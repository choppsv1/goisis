//
// -*- coding: utf-8 -*-
//
// December 28 2017, Christian E. Hopps <chopps@gmail.com>
//
//                           if not Hello
//  processPDUs (main rtn) <- inpkts <-- FrameToPDU <- readPackets (circuit 1 go rtn)
//      |                         ^
//      |                         | ...
//      V                         |
//  ProcessOtherPDU (Link)        \-- FrameToPDU <- readPackets (circuit N go rtn)
//
//  - Hello PDUs are processed in the circuit's go rtn
//  - inpkts is actually 2 channels for LSP and SNP separately.
//
package main

import (
	"bytes"
	"github.com/choppsv1/goisis/clns"
	"github.com/choppsv1/goisis/ether"
	"github.com/choppsv1/goisis/tlv"
	"io"
	"syscall"
)

// readPackets is a go routine to read packets from link and writes to a channel
// after doing some basic validation and baking of the frame into a PDU.
func (base *CircuitBase) readPackets(c Circuit) {
	debug(DbgFPkt, "Starting to read packets on %s\n", base)
	for {
		pkt, from, err := base.sock.ReadPacket()
		if err != nil {
			if err == io.EOF {
				debug(DbgFPkt, "EOF reading from %s, will stop reading from link\n", base)
				return
			}
			debug(DbgFPkt, "Error reading from link %s: %s\n", base.intf.Name, err)
			continue
		}
		// debug(DbgFPkt, "Read packet on %s len(%d)\n", base.link, len(frame.pkt))

		// Do Frame Validation and get PDU.
		pdu := c.FrameToPDU(pkt, from)
		if pdu == nil {
			continue
		}
		// Receive IIH inside the circuit's go routine in parallel.
		switch pdu.pdutype {
		case clns.PDUTypeIIHLANL1:
			l, _ := pdu.pdutype.GetPDULevel()
			RecvLANHello(pdu.link, pdu, l)
		case clns.PDUTypeIIHLANL2:
			l, _ := pdu.pdutype.GetPDULevel()
			RecvLANHello(pdu.link, pdu, l)
		case clns.PDUTypeLSPL1, clns.PDUTypeLSPL2:
			debug(DbgFPkt, "Sending LSP from %s to UPD", base)
			base.updb[pdu.li].InputLSP(pdu.payload, pdu.pdutype, pdu.tlvs)
		case clns.PDUTypeCSNPL1, clns.PDUTypeCSNPL2:
			base.snppkt <- pdu
		default:
			debug(DbgFPkt, "Unknown PDU type %s on %s\n", pdu.pdutype, base.intf.Name)
		}

	}
}

// writePackets is a go routine to read packets from a channel and output to link.
func (base *CircuitBase) writePackets() {
	debug(DbgFPkt, "Starting to write packets on %s\n", base)
	for {
		select {
		case pkt := <-base.outpkt:
			addr := ether.Frame(pkt).GetDst()
			debug(DbgFPkt, "[socket] <- len %d from link channel %s to %s\n",
				len(pkt),
				base.intf.Name,
				addr)
			n, err := base.sock.WritePacket(pkt, addr)
			if err != nil {
				debug(DbgFPkt, "Error writing packet to %s: %s\n",
					base.intf.Name, err)
			} else {
				debug(DbgFPkt, "Wrote packet len %d/%d to %s\n",
					len(pkt), n, base.intf.Name)
			}
		case <-base.quit:
			debug(DbgFPkt, "Got quit signal for %s, will stop writing to link\n", base)
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

	debug(DbgFPkt, " <- len %d from circuit %s to %s from %s llclen %d\n",
		len(frame), c.intf.Name, pdu.dst, pdu.src, eframe.GetTypeLen())

	var llc []byte
	pdu.payload, llc, err = eframe.ValidateFrame(ourSNPA)
	if err != nil {
		if err == ether.ErrOurFrame(true) {
			debug(DbgFPkt, "Dropping our own frame")
		} else {
			debug(DbgFPkt, "Dropping frame due to: %s", err)
		}
		return nil
	}

	pdu.payload, pdu.pdutype, err = clns.ValidatePDU(llc, pdu.payload, GlbISType, c.lf)
	if err != nil {
		debug(DbgFPkt, "Dropping IS-IS frame due to: %s", err)
		return nil
	}

	l, err := pdu.pdutype.GetPDULevel()
	if err != nil {
		debug(DbgFPkt, "Dropping frame due to: %s", err)
		return nil
	}
	pdu.l = l

	pdu.link = c.levlink[l-1]
	if pdu.link == nil {
		debug(DbgFPkt, "Dropping frame as L%s not enabled on %s", l, c)
		return nil
	}

	// Check for expected ether dst (correct mcast or us)
	if !bytes.Equal(pdu.dst, clns.AllLxIS[l-1]) {
		if !bytes.Equal(pdu.dst, c.getOurSNPA()) {

			debug(DbgFPkt, "Dropping IS-IS frame to non-IS-IS address, exciting extensions in use!?")
			return nil
		}
	}

	tlvp := tlv.Data(pdu.payload[clns.PDUTLVOffMap[pdu.pdutype]:])
	pdu.tlvs, err = tlvp.ParseTLV()
	if err != nil {
		debug(DbgFPkt, "Dropping frame on %s due to TLV error %s", c, err)
		return nil
	}

	// XXX sanity check from == src?

	return pdu
}

//
// processPDUs handles all non-IIH incoming packets (frames) serially. If performance
// is an issue we could parallelize this based on packet type etc..
//
func processPDUs(cdb *CircuitDB) {
	for {
		select {
		case pdu := <-cdb.snppkts:
			err := pdu.link.ProcessSNP(pdu)
			if err != nil {
				debug(DbgFPkt, "Error processing packet: %s\n", err)
			}
		}
	}
}

// ----------------------------------------------------------------------------
// Currently all received packets are handled serially in the order they arrive
// (using a single go routine). However we may change this (specifically for
// IIH) to handle those in the receiving go routines.
// ----------------------------------------------------------------------------

// ProcessSNP handle non-IIH PDUs, these are currently all handled in the
// same go routine.
func (link *LinkLAN) ProcessSNP(pdu *RecvPDU) error {
	// Validate ethernet values.
	// var src, dst [clns.SNPALen]byte
	// l, err := pdu.pdutype.GetPDULevel()
	// if err != nil {
	// 	return err
	// }

	switch pdu.pdutype {
	case clns.PDUTypeCSNPL1:
		debug(DbgFPkt, "INFO: ignoring CSNPL1 on %s for now", link)
	case clns.PDUTypeCSNPL2:
		debug(DbgFPkt, "INFO: ignoring CSNPL2 on %s for now", link)
	case clns.PDUTypePSNPL1:
		debug(DbgFPkt, "INFO: ignoring PSNPL1 on %s for now", link)
	case clns.PDUTypePSNPL2:
		debug(DbgFPkt, "INFO: ignoring PSNPL2 on %s for now", link)
	default:
		panic("Illegal PDU type")
	}
	return nil
}
