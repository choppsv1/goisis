package main

// Circuits are physical interfaces in IS-IS.

import (
	"fmt"
	"github.com/choppsv1/goisis/clns"
	"github.com/choppsv1/goisis/ether"
	"github.com/choppsv1/goisis/raw"
	"github.com/choppsv1/goisis/tlv"
	"golang.org/x/net/bpf"
	"net"
	"syscall"
)

//
// Circuit is an IS-IS/CLNS physical interface.
//
type Circuit interface {
	ClosePDU(ether.Frame, []byte) error
	FrameToPDU([]byte, syscall.Sockaddr) *RecvPDU
	OpenPDU(clns.PDUType, net.HardwareAddr) (ether.Frame, []byte, []byte)
}

//
// Link represents level dependent operations on a circuit.
//
type Link interface {
	DISInfoChanged()
	ProcessPDU(*RecvPDU) error
	UpdateAdj(*RecvPDU) error
	UpdateAdjState(*Adj, map[tlv.Type][]tlv.Data) error
}

// PDU is a type that holds a valid IS-IS PDU.
type PDU struct {
	payload []byte
	pdutype clns.PDUType
	level   clns.Level
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
	intf   *net.Interface
	sock   raw.IntfSocket
	inpkt  chan<- *RecvPDU
	outpkt chan []byte
	quit   <-chan bool
}

func (base *CircuitBase) String() string {
	return fmt.Sprintf("CircuitBase(%s)", base.intf.Name)
}

//
// NewCircuitBase allocates and initializes a new CircuitBase structure.
//
func NewCircuitBase(ifname string, inpkt chan<- *RecvPDU, quit chan bool, filter []bpf.RawInstruction) (*CircuitBase, error) {
	var err error

	base := &CircuitBase{
		inpkt:  inpkt,
		outpkt: make(chan []byte),
		quit:   quit,
	}

	base.intf, err = net.InterfaceByName(ifname)
	if err != nil {
		return nil, err
	}
	// Get raw socket connection for interface send/receive

	base.sock, err = raw.NewInterfaceSocket(base.intf.Name)
	if err != nil {
		return nil, err
	}

	err = base.sock.SetBPF(filter)
	if err != nil {
		fmt.Printf("Error setting filter: %s\n", err)
		return nil, err
	}

	return base, nil
}
