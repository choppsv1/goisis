package main

import (
	"fmt"
	"github.com/choppsv1/goisis/ether"
	"github.com/choppsv1/goisis/raw"
	"github.com/choppsv1/goisis/tlv"
	"golang.org/x/net/bpf"
	"io"
	"net"
	"syscall"
)

// ================================
// Link is an IS-IS/CLNS interface.
// ================================
type Link interface {
	DISInfoChanged(level int)
	GetOurSNPA() net.HardwareAddr
	ProcessPacket(*RecvFrame) error
	UpdateAdjState(*Adj, map[tlv.Type][]tlv.Data) error
}

// --------------------------------------------------------
// Frame is a type passed by value for handling raw packets
// --------------------------------------------------------
type RecvFrame struct {
	pkt  []byte
	from syscall.Sockaddr
	link Link
}

// ----------------------------------------------------------------
// LinkCommon collects common functionality from all types of links
// ----------------------------------------------------------------
type LinkCommon struct {
	link   Link
	intf   *net.Interface
	sock   raw.IntfSocket
	inpkt  chan<- *RecvFrame
	outpkt chan []byte
	quit   <-chan bool
}

func (common *LinkCommon) String() string {
	return fmt.Sprintf("Link(%s)", common.intf.Name)
}

// readPackets is a go routine to read packets from link and input to channel.
func (common *LinkCommon) readPackets() {
	var err error

	debug(DbgFPkt, "Starting to read packets on %s\n", common)
	for {
		frame := RecvFrame{
			link: common.link,
		}
		frame.pkt, frame.from, err = common.sock.ReadPacket()
		if err != nil {
			if err == io.EOF {
				debug(DbgFPkt, "EOF reading from %s, will stop reading from link\n", common)
				return
			}
			debug(DbgFPkt, "Error reading from link %s: %s\n", common.intf.Name, err)
			continue
		}
		// debug(DbgFPkt, "Read packet on %s len(%d)\n", common.link, len(frame.pkt))
		// XXX Do some early validation before sending on channel.
		common.inpkt <- &frame
	}
}

// writePackets is a go routine to read packets from a channel and output to link.
func (common *LinkCommon) writePackets() {
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

// -------------------------------------------------------------
// NewLink allocates and initializes a new LinkCommon structure.
// -------------------------------------------------------------
func NewLink(link Link, ifname string, inpkt chan<- *RecvFrame, quit chan bool) (*LinkCommon, error) {
	var err error

	common := &LinkCommon{
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
