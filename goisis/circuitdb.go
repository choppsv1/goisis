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
	cdb := new(CircuitDB)
	cdb.links = make(map[string]interface{})
	cdb.iihpkts = make(chan *RecvPDU)
	cdb.snppkts = make(chan *RecvPDU)
	return cdb
}

func (cdb *CircuitDB) SetAllSRM(lspid *clns.LSPID) {
}

func (cdb *CircuitDB) NewCircuit(ifname string, updb [2]*update.DB, lf clns.LevelFlag) (*CircuitLAN, error) {
	cb, err := NewCircuitBase(ifname,
		lf,
		cdb.iihpkts,
		cdb.snppkts,
		GlbQuit)
	if err != nil {
		return nil, err
	}
	// Check interface type and allocate LAN or P2P
	return NewCircuitLAN(cb, lf)
}
