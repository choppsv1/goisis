package main

import (
	"bytes"
	"fmt"
	"github.com/choppsv1/goisis/clns"
	"github.com/choppsv1/goisis/pkt"
	"github.com/choppsv1/goisis/tlv"
	"time"
)

//
// SendLANHellos is a go routine that watches for hello timer events and sends
// hellos when they are received.
//
func SendLANHellos(link *LinkLAN, interval int, quit chan bool) error {
	debug(DbgFPkt, "Sending hellos on %s with interval %d", link, interval)
	ival := time.Second * time.Duration(interval)
	ticker := time.NewTicker(ival) // XXX replace with jittered timer.
	go func() {
		sendLANHello(link)
		debug(DbgFPkt, "Sent initial IIH on %s entering ticker loop", link)
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
		debug(DbgFPkt, "Stop sending IIH on %s", link)
	}
	return nil
}

func sendLANHello(link *LinkLAN) error {
	var err error
	var pdutype clns.PDUType

	debug(DbgFPkt, "Sending IIH on %s", link)

	if link.level == 1 {
		pdutype = clns.PDUTypeIIHLANL1
	} else {
		pdutype = clns.PDUTypeIIHLANL2
	}

	// XXX we want the API to return payload here and later we convert frame
	// in close so that we aren't dependent on ethernet
	etherp, _, iihp := link.circuit.OpenPDU(pdutype, clns.AllLxIS[link.lindex])

	// ----------
	// IIH Header
	// ----------

	iihp[clns.HdrIIHLANCircType] = uint8(link.level)
	copy(iihp[clns.HdrIIHLANSrcID:], GlbSystemID)
	pkt.PutUInt16(iihp[clns.HdrIIHLANHoldTime:],
		uint16(link.helloInt*link.holdMult))
	iihp[clns.HdrIIHLANPriority] = byte(clns.DefHelloPri) & 0x7F
	copy(iihp[clns.HdrIIHLANLANID:], link.lanID[:])
	endp := iihp[clns.HdrIIHLANSize:]

	// --------
	// Add TLVs
	// --------

	if link.level == 1 {
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

	addrs := link.adjdb.GetAdjSNPA()
	if len(addrs) > 0 {
		t, err := tlv.Open(endp, tlv.TypeISNeighbors, nil)
		if err != nil {
			debug(DbgFPkt, "Error Opening %s TLVs: %s", t.Type, err)
			return err
		}
		for _, addr := range addrs {
			var b tlv.Data
			alen := len(addr)
			if b, err = t.Alloc(len(addr)); err != nil {
				debug(DbgFPkt, "Error alocating %d space for %s TLVs: %s", alen, t.Type, err)
				return err
			}
			copy(b, addr)
		}
		endp = t.Close()
	}

	// Pad to MTU
	for cap(endp) > 1 {
		endp, err = tlv.AddPadding(endp)
		if err != nil {
			debug(DbgFPkt, "Error adding Padding TLVs: %s", err)
			return err
		}
	}

	link.circuit.ClosePDU(etherp, endp)

	// ---------------
	// Send the packet
	// ---------------
	link.circuit.outpkt <- etherp

	return nil
}

// ErrIIH is a general error in IIH packet processing
type ErrIIH string

func (e ErrIIH) Error() string {
	return fmt.Sprintf("ErrIIH: %s", string(e))
}

//
// RecvLANHello receives IIH from on a given LAN link
//
func RecvLANHello(link Link, pdu *RecvPDU, level clns.Level) error {
	debug(DbgFPkt, "IIH: processign from %s", pdu.src)

	tlvs := pdu.tlvs

	// For level 1 we must be in the same area.
	if level == 1 {
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
