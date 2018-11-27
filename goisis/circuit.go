package main

// Circuits are physical interfaces in IS-IS.

import (
	"fmt"
	"github.com/choppsv1/goisis/clns"
	"github.com/choppsv1/goisis/ether"
	"github.com/choppsv1/goisis/goisis/update"
	"github.com/choppsv1/goisis/pkt"
	"github.com/choppsv1/goisis/raw"
	"github.com/choppsv1/goisis/tlv"
	"golang.org/x/net/bpf"
	"net"
	"syscall"
)

// -------
// Globals
// -------

// ourSNPA keeps track of all of our SNPA to check for looped back frames
var ourSNPA = make(map[ether.MAC]bool)

// llcTemplate are the static values we use int he LLC header.
var llcTemplate = []uint8{
	clns.LLCSSAP,
	clns.LLCDSAP,
	clns.LLCControl,
}

// clnsTemplate are the static values we use in the CLNS header.
var clnsTemplate = []uint8{
	clns.IDRPISIS,
	0, // Header Length
	clns.Version,
	clns.SysIDLen,
	0, // PDU Type
	clns.Version2,
	0,            // Reserved
	clns.MaxArea, // Max Area
}

// ----------
// Interfaces
// ----------

//
// Circuit is an IS-IS/CLNS physical interface.
//
type Circuit interface {
	IsP2P() bool
	ClearFlag(flag update.SxxFlag, lspid *clns.LSPID, li clns.LIndex)
	ClosePDU(ether.Frame, []byte)
	FrameToPDU([]byte, syscall.Sockaddr) *RecvPDU
	OpenPDU(clns.PDUType, net.HardwareAddr) (ether.Frame, []byte, []byte, []byte)
	OpenFrame(net.HardwareAddr) (ether.Frame, []byte)
	SetFlag(flag update.SxxFlag, lspid *clns.LSPID, li clns.LIndex)
}

// -----
// Types
// -----

// PDU is a type that holds a valid IS-IS PDU.
type PDU struct {
	payload []byte
	pdutype clns.PDUType
	l       clns.Level
	li      clns.LIndex
	tlvs    map[tlv.Type][]tlv.Data
}

//
// RecvPDU is a type passed by value for handling frames after some
// validation/baking.
type RecvPDU struct {
	PDU
	link Link
	src  net.HardwareAddr
	dst  net.HardwareAddr
}

//
// CircuitBase collects common functionality from all types of circuits
//
type CircuitBase struct {
	intf    *net.Interface
	sock    raw.IntfSocket
	lf      clns.LevelFlag
	cdb     *CircuitDB
	updb    [2]*update.DB
	v4addrs []net.IPNet
	v6addrs []net.IPNet
	iihpkt  chan<- *RecvPDU
	snppkt  chan<- *RecvPDU
	outpkt  chan []byte
	quit    <-chan bool
}

func (cb *CircuitBase) String() string {
	return fmt.Sprintf("CircuitBase(%s)", cb.intf.Name)
}

//
// NewCircuitBase allocates and initializes a new CircuitBase structure.
//
func NewCircuitBase(ifname string, lf clns.LevelFlag, cdb *CircuitDB, updb [2]*update.DB, quit chan bool) (*CircuitBase, error) {
	var err error

	cb := &CircuitBase{
		lf:     lf,
		cdb:    cdb,
		updb:   updb,
		iihpkt: cdb.iihpkts,
		snppkt: cdb.snppkts,
		outpkt: make(chan []byte),
		quit:   quit,
	}

	cb.intf, err = net.InterfaceByName(ifname)
	if err != nil {
		return nil, err
	}

	// Get the L3 addrs for this circuit
	var addrs []net.Addr
	if addrs, err = cb.intf.Addrs(); err != nil {
		// fmt.Fprintf(os.Stderr, "Error intf.Addrs: %s\n", err)
		return nil, err
	}
	for _, addr := range addrs {
		ipnet := addr.(*net.IPNet)
		ipv4 := ipnet.IP.To4()
		if ipv4 != nil {
			ipnet.IP = ipv4
			cb.v4addrs = append(cb.v4addrs, *ipnet)
		} else {
			cb.v6addrs = append(cb.v6addrs, *ipnet)
		}
	}

	// Get raw socket connection for interface send/receive

	cb.sock, err = raw.NewInterfaceSocket(cb.intf.Name)
	if err != nil {
		return nil, err
	}

	return cb, nil
}

// SetBPF sets the BPF filter for a citcuit
func (cb *CircuitBase) SetBPF(filter []bpf.RawInstruction) error {

	err := cb.sock.SetBPF(filter)
	if err != nil {
		fmt.Printf("Error setting filter: %s\n", err)
	}
	return err

}

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

// getOurSNPA returns the SNPA for this circuit
func (c *CircuitLAN) getOurSNPA() net.HardwareAddr {
	return c.CircuitBase.intf.HardwareAddr
}

//
// NewCircuitLAN creates a LAN circuit for a given IS-IS level.
//
func NewCircuitLAN(cb *CircuitBase, lf clns.LevelFlag) (*CircuitLAN, error) {
	var err error

	c := &CircuitLAN{
		CircuitBase: cb,
	}

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
	if err = cb.SetBPF(filter); err != nil {
		return nil, err
	}

	// Record our SNPA in the map of our SNPA
	ourSNPA[ether.MACKey(c.CircuitBase.intf.HardwareAddr)] = true

	for l := clns.Level(1); l <= 2; l++ {
		if lf.IsLevelEnabled(l) {
			li := l.ToIndex()
			c.levlink[li] = NewLinkLAN(c, li, cb.updb[li], cb.quit)
		}
	}

	go c.readPackets(c)
	go c.writePackets()

	return c, nil
}

// OpenFrame returns a full sized ethernet frame with the headers
// semi-initialized, a call to CloseFrame completes the initialization.
func (c *CircuitLAN) OpenFrame(dst net.HardwareAddr) (ether.Frame, []byte) {
	etherb := make([]byte, c.intf.MTU+14)
	etherp := ether.Frame(etherb)
	copy(etherp[ether.HdrEthDest:], dst)
	copy(etherp[ether.HdrEthSrc:], c.intf.HardwareAddr)

	debug(DbgFPkt, "OpenFrame dst: %s, src: %s\n",
		etherp.GetDst(), etherp.GetSrc(), etherp.GetTypeLen())

	llcp := etherp[ether.HdrEthSize:]
	copy(llcp, llcTemplate)

	return etherp, llcp[ether.HdrLLCSize:]

}

// CloseFrame closes the ethernet frame (sets the len value).
func CloseFrame(etherp ether.Frame, len int) ether.Frame {
	etherp.SetTypeLen(len + ether.HdrLLCSize)
	etherp = etherp[:ether.HdrEthSize+ether.HdrLLCSize+len]
	debug(DbgFPkt, "CloseFrame dst: %s, src: %s framelen %d\n",
		etherp.GetDst(), etherp.GetSrc(), etherp.GetTypeLen())
	return etherp
}

//
// OpenPDU returns a frame buffer sized to the MTU of the interface (including
// the L2 frame header) after initializing the CLNS header fields.
//
func (c *CircuitLAN) OpenPDU(pdutype clns.PDUType, dst net.HardwareAddr) (ether.Frame, []byte, []byte, []byte) {
	etherp, clnsp := c.OpenFrame(dst)
	copy(clnsp, clnsTemplate)

	clnsp[clns.HdrCLNSPDUType] = uint8(pdutype)
	hdrlen := clns.HdrLenMap[pdutype]
	clnsp[clns.HdrCLNSLen] = hdrlen

	return etherp, clnsp, clnsp[clns.HdrCLNSSize:], clnsp[hdrlen:]
}

//
// ClosePDU finalizes the PDU length fields given endp "pointer"
//
func (c *CircuitLAN) ClosePDU(etherp ether.Frame, endp []byte) {
	ethlen := tlv.GetOffset([]byte(etherp), endp)
	epayloadlen := ethlen - ether.HdrEthSize
	pdutype := etherp[ether.HdrEthSize+ether.HdrLLCSize+clns.HdrCLNSPDUType]

	// Calculate the packet size and fill in various places
	elenoff := ether.HdrEthSize + ether.HdrLLCSize + clns.PDULenOffMap[clns.PDUType(pdutype)]
	pdulen := epayloadlen - ether.HdrLLCSize
	pkt.PutUInt16(etherp[elenoff:], uint16(pdulen))

	etherp = etherp[0 : epayloadlen+ether.HdrEthSize]
	etherp.SetTypeLen(epayloadlen)

	debug(DbgFPkt, "Closing PDU with pdulen %d payload %d framelen %d",
		pdulen, epayloadlen, len(etherp))
}

// SetFlag sets the given flag for the given LSPID for the given level (li)
func (c *CircuitLAN) SetFlag(flag update.SxxFlag, lspid *clns.LSPID, li clns.LIndex) {
	debug(DbgFFlags, "CircuitLAN: Set %s %s %s for %s", flag, *lspid, li.ToLevel(), c)
	c.levlink[li].setFlag(flag, lspid)
}

// ClearFlag sets the given flag for the given LSPID for the given level (li)
func (c *CircuitLAN) ClearFlag(flag update.SxxFlag, lspid *clns.LSPID, li clns.LIndex) {
	debug(DbgFFlags, "CircuitLAN: Clear %s %s %s for %s", flag, *lspid, li.ToLevel(), c)
	c.levlink[li].clearFlag(flag, lspid)
}

func (c *CircuitLAN) IsP2P() bool {
	return false
}
