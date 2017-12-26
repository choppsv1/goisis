package main

// Circuits are physical interfaces in IS-IS.

import (
	"fmt"
	"github.com/choppsv1/goisis/clns"
	"github.com/choppsv1/goisis/ether"
	"github.com/choppsv1/goisis/raw"
	"github.com/choppsv1/goisis/tlv"
	"golang.org/x/net/bpf"
	"io"
	"net"
	"syscall"
)

//
// Circuit is an IS-IS/CLNS physical interface.
//
type Circuit interface {
	FrameToPDU([]byte, syscall.Sockaddr) *RecvPDU
}

// Link is an represents level dependent operations on a circuit.
type Link interface {
	DISInfoChanged()
	ProcessPDU(*RecvPDU) error
	UpdateAdj(*RecvPDU) error
	UpdateAdjState(*Adj, map[tlv.Type][]tlv.Data) error
}

//
// RecvPDU is a type passed by value for handling frames after some
// validation/baking.
type RecvPDU struct {
	payload []byte
	pdutype clns.PDUType
	tlvs    map[tlv.Type][]tlv.Data
	link    Link
	src     net.HardwareAddr
	dst     net.HardwareAddr
}

//
// CircuitBase collects common functionality from all types of circuits
//
type CircuitBase struct {
	link   Circuit
	intf   *net.Interface
	sock   raw.IntfSocket
	inpkt  chan<- *RecvPDU
	outpkt chan []byte
	quit   <-chan bool
}

func (common *CircuitBase) String() string {
	return fmt.Sprintf("Link(%s)", common.intf.Name)
}

// readPackets is a go routine to read packets from link and input to channel.
func (common *CircuitBase) readPackets() {
	debug(DbgFPkt, "Starting to read packets on %s\n", common)
	for {
		pkt, from, err := common.sock.ReadPacket()
		if err != nil {
			if err == io.EOF {
				debug(DbgFPkt, "EOF reading from %s, will stop reading from link\n", common)
				return
			}
			debug(DbgFPkt, "Error reading from link %s: %s\n", common.intf.Name, err)
			continue
		}
		// debug(DbgFPkt, "Read packet on %s len(%d)\n", common.link, len(frame.pkt))

		// Do Frame Validation and get PDU.
		pdu := common.link.FrameToPDU(pkt, from)
		if pdu == nil {
			continue
		}

		pdu.payload, err = clns.ValidatePDU(pdu.payload)
		if err != nil {
			continue
		}

		common.inpkt <- pdu
	}
}

// writePackets is a go routine to read packets from a channel and output to link.
func (common *CircuitBase) writePackets() {
	debug(DbgFPkt, "Starting to write packets on %s\n", common)
	for {
		debug(DbgFPkt, "XXX select in writePackets")
		select {
		case pkt := <-common.outpkt:
			addr := ether.Frame(pkt).GetDst()
			debug(DbgFPkt, "[socket] <- len %d from link channel %s to %s\n",
				len(pkt),
				common.intf.Name,
				addr)
			n, err := common.sock.WritePacket(pkt, addr)
			if err != nil {
				debug(DbgFPkt, "Error writing packet to %s: %s\n",
					common.intf.Name, err)
			} else {
				debug(DbgFPkt, "Wrote packet len %d/%d to %s\n",
					len(pkt), n, common.intf.Name)
			}
		case <-common.quit:
			debug(DbgFPkt, "Got quit signal for %s, will stop writing to link\n", common)
			return
		}
	}
}

//
// NewCircuitBase allocates and initializes a new CircuitBase structure.
//
func NewCircuitBase(link Circuit, ifname string, inpkt chan<- *RecvPDU, quit chan bool) (*CircuitBase, error) {
	var err error

	common := &CircuitBase{
		link:   link,
		inpkt:  inpkt,
		outpkt: make(chan []byte),
		quit:   quit,
	}

	common.intf, err = net.InterfaceByName(ifname)
	if err != nil {
		return nil, err
	}
	// Get raw socket connection for interface send/receive

	common.sock, err = raw.NewInterfaceSocket(common.intf.Name)
	if err != nil {
		return nil, err
	}

	// IS-IS BPF filter
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

	err = common.sock.SetBPF(filter)
	if err != nil {
		fmt.Printf("Error setting filter: %s\n", err)
		return nil, err
	}

	go common.readPackets()
	go common.writePackets()

	return common, nil
}
