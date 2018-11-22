package main

import (
	"github.com/choppsv1/goisis/clns"
	"github.com/choppsv1/goisis/goisis/update"
)

//
// CircuitDB is a database of circuits we run on.
//
type CircuitDB struct {
	links   map[string]interface{}
	iihpkts chan *RecvPDU
	snppkts chan *RecvPDU
}

//
// NewCircuitDB allocate and initialize a new circuit database.
//
func NewCircuitDB() *CircuitDB {
	return &CircuitDB{
		links:   make(map[string]interface{}),
		iihpkts: make(chan *RecvPDU),
		snppkts: make(chan *RecvPDU),
	}
}

func (cdb *CircuitDB) SetAllSRM(lspid *clns.LSPID) {
}

func (cdb *CircuitDB) NewCircuit(ifname string, lf clns.LevelFlag, updb [2]*update.DB) (*CircuitLAN, error) {
	cb, err := NewCircuitBase(ifname,
		lf,
		updb,
		cdb.iihpkts,
		cdb.snppkts,
		GlbQuit)
	if err != nil {
		return nil, err
	}
	// Check interface type and allocate LAN or P2P
	return NewCircuitLAN(cb, lf)
}
