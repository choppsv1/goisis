package main

import (
	"github.com/choppsv1/goisis/clns"
	"github.com/choppsv1/goisis/pkt"
	"github.com/choppsv1/goisis/tlv"
	"time"
)

// sendHellos is a go routine that watches for hello timer events and sends
// hellos when they are received.
func sendLANHellos(link *LANLink, interval int, quit chan bool) error {
	debug.Printf("Sending hellos on %s with interval %d", link, interval)
	ival := time.Second * time.Duration(interval)
	ticker := time.NewTicker(ival) // XXX replace with jittered timer.
	go func() {
		sendLANHello(link)
		for range ticker.C {
			sendLANHello(link)
		}
	}()
	// Wait for quit ... do we need to do this or will the ticker stop
	// automatically? What about when ticker goes out of scope will it be
	// GCed?
	select {
	case <-quit:
		ticker.Stop()
		debug.Printf("Stop sending IIH on %s", link)
	}
	return nil
}

func sendLANHello(link *LANLink) error {
	var err error
	var pdutype clns.PDUType

	debug.Printf("Sending IIH on %s", link)

	if link.level == 1 {
		pdutype = clns.PDUTypeIIHLANL1
	} else {
		pdutype = clns.PDUTypeIIHLANL2
	}

	// XXX we want the API to return payload here and later we convert frame
	// in close so that we aren't dependent on ethernet
	etherp, _, iihp := link.OpenPDU(pdutype, clns.AllLxIS[link.lindex])

	// ----------
	// IIH Header
	// ----------

	iihp[clns.HdrIIHLANCircType] = uint8(link.level)
	copy(iihp[clns.HdrIIHLANSrcID:], SystemID)
	pkt.PutUInt16(iihp[clns.HdrIIHLANHoldTime:],
		uint16(link.helloInt*link.holdMult))
	iihp[clns.HdrIIHLANPriority] = byte(clns.DefHelloPri) & 0x7F
	copy(iihp[clns.HdrIIHLANLANID:], link.lanID[:])
	endp := iihp[clns.HdrIIHLANSize:]

	// --------
	// Add TLVs
	// --------

	if link.level == 1 {
		endp, err = tlv.AddArea(endp, AreaID)
		if err != nil {
			return err
		}
	}

	endp, err = tlv.AddNLPID(endp, NLPID)
	if err != nil {
		return err
	}

	// Pad to MTU
	for cap(endp) > 1 {
		endp, err = tlv.AddPadding(endp)
		if err != nil {
			return err
		}
	}

	link.ClosePDU(etherp, endp)

	// ---------------
	// Send the packet
	// ---------------
	link.outpkt <- etherp

	return nil
}
