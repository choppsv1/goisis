package main

import (
	"fmt"
	"github.com/choppsv1/goisis/clns"
	"github.com/choppsv1/goisis/ether"
	"github.com/choppsv1/goisis/pkt"
	"github.com/choppsv1/goisis/tlv"
	"golang.org/x/net/bpf"
	"net"
)

// ourSNPA keeps track of all of our SNPA to check for looped back frames
var ourSNPA = make(map[ether.MAC]bool)

//
// CircuitLAN is a structure holding information on a IS-IS LAN circuit.
//
type CircuitLAN struct {
	*CircuitBase
	levlink [2]*LinkLAN
}

func (c *CircuitLAN) String() string {
	return fmt.Sprintf("CircuitLAN(%s)", c.CircuitBase)
}

//
// GetOurSNPA returns the SNPA for this circuit
//
func (c *CircuitLAN) getOurSNPA() net.HardwareAddr {
	return c.CircuitBase.intf.HardwareAddr
}

//
// NewCircuitLAN creates a LAN circuit for a given IS-IS level.
//
func NewCircuitLAN(ifname string, inpkt chan<- *RecvPDU, quit chan bool, levelf clns.LevelFlag) (*CircuitLAN, error) {
	var err error

	c := &CircuitLAN{}

	// IS-IS LAN BPF filter
	filter, err := bpf.Assemble([]bpf.Instruction{
		// 0: Load 2 bytes from offset 12 (ethertype)
		bpf.LoadAbsolute{Off: 12, Size: 2},
		// 1: Jump fwd + 1 if 0x8870 (jumbo) otherwise fwd + 0 (continue)
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x8870, SkipTrue: 1},
		// 2: Jump fwd + 3 if > 1500 (drop non-IEEE 802.2 LLC) otherwise fwd + 0 (continue)
		bpf.JumpIf{Cond: bpf.JumpGreaterThan, Val: 1500, SkipTrue: 3},
		// 3: Load 2 bytes from offset 14 (llc src, dst)
		bpf.LoadAbsolute{Off: 14, Size: 2},
		// 4: Jump fwd + 0 if 0xfefe (keep) otherwise fwd + 1 (drop)
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: 0xfefe, SkipTrue: 1},
		// 5: Keep
		bpf.RetConstant{Val: 0xffff},
		// 6: Drop
		bpf.RetConstant{Val: 0},
	})
	if err != nil {
		return nil, err
	}

	c.CircuitBase, err = NewCircuitBase(ifname, inpkt, quit, filter)
	if err != nil {
		return nil, err
	}

	// Record our SNPA in the map of our SNPA
	ourSNPA[ether.MACKey(c.CircuitBase.intf.HardwareAddr)] = true

	for i := uint(0); i < 2; i++ {
		if (levelf & (1 << i)) != 0 {
			c.levlink[i] = NewLinkLAN(c, clns.LIndex(i), quit)
		}
	}

	go c.readPackets(c)
	go c.writePackets()

	return c, nil
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
func (c *CircuitLAN) OpenPDU(pdutype clns.PDUType, dst net.HardwareAddr) (ether.Frame, []byte, []byte) {
	etherp := make([]byte, c.intf.MTU+14)

	copy(etherp[ether.HdrEthDest:], dst)
	copy(etherp[ether.HdrEthSrc:], c.intf.HardwareAddr)
	clnsp := etherp[ether.HdrEthSize:]
	copy(clnsp, clnsTemplate)
	clnsp[clns.HdrCLNSPDUType] = uint8(pdutype)
	clnsp[clns.HdrCLNSLen] = clns.HdrLenMap[pdutype]
	return etherp, clnsp, clnsp[clns.HdrCLNSSize:]
}

//
// ClosePDU finalizes the PDU length fields given endp "pointer"
//
func (c *CircuitLAN) ClosePDU(etherp ether.Frame, endp []byte) error {
	ethlen := tlv.GetOffset([]byte(etherp), endp)
	epayloadlen := ethlen - ether.HdrEthSize
	pdutype := etherp[ether.HdrEthSize+ether.HdrLLCSize+clns.HdrCLNSPDUType]

	// Calculate the packet size and fill in various places
	elenoff := ether.HdrEthSize + clns.PDULenOffMap[clns.PDUType(pdutype)]
	pdulen := epayloadlen - ether.HdrLLCSize
	pkt.PutUInt16(etherp[elenoff:], uint16(pdulen))

	etherp = etherp[0 : epayloadlen+ether.HdrEthSize]
	etherp.SetTypeLen(epayloadlen)

	debug(DbgFPkt, "Closing PDU with pdulen %d payload %d framelen %d",
		pdulen, epayloadlen, len(etherp))
	return nil
}
