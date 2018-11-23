package main

import (
	"github.com/choppsv1/goisis/clns"
	"github.com/choppsv1/goisis/goisis/update"
)

//
// CircuitDB is a database of circuits we run on.
//
type CircuitDB struct {
	circuits map[string]Circuit
	flagsC   chan update.ChgSxxFlag
	iihpkts  chan *RecvPDU
	snppkts  chan *RecvPDU
}

// NewCircuitDB allocate and initialize a new circuit database.
func NewCircuitDB() *CircuitDB {
	cdb := &CircuitDB{
		circuits: make(map[string]Circuit),
		flagsC:   make(chan update.ChgSxxFlag),
		iihpkts:  make(chan *RecvPDU),
		snppkts:  make(chan *RecvPDU),
	}

	go cdb.processFlags()

	return cdb
}

// NewCircuit creates a circuit enabled for the given levels.
func (cdb *CircuitDB) NewCircuit(ifname string, lf clns.LevelFlag, updb [2]*update.DB) (*CircuitLAN, error) {
	cb, err := NewCircuitBase(ifname,
		lf,
		cdb,
		updb,
		GlbQuit)
	if err != nil {
		return nil, err
	}
	// Check interface type and allocate LAN or P2P
	cll, err := NewCircuitLAN(cb, lf)
	cdb.circuits[ifname] = cll
	return cll, err
}

// // SetAllFlag sets the given flag for the given LSPID on all circuits except 'not'
// func (cdb *CircuitDB) SetAllFlag(flag update.SxxFlag, lspid *clns.LSPID, li clns.LIndex, not Circuit) {
// 	for _, c := range cdb.circuits {
// 		if c == not {
// 			continue
// 		}
// 		c.SetFlag(flag, lspid, li)
// 	}
// }

// // ClearAllFlag clears the given flag for the given LSPID on all circuits except 'not'
// func (cdb *CircuitDB) ClearAllFlag(flag update.SxxFlag, lspid *clns.LSPID, li clns.LIndex, not Circuit) {
// 	for _, c := range cdb.circuits {
// 		if c == not {
// 			continue
// 		}
// 		c.ClearFlag(flag, lspid, li)
// 	}
// }

func (cdb *CircuitDB) processFlag(cf *update.ChgSxxFlag) {
	if !cf.All {
		panic("Invalid non-all sent to circuitDB")
	}
	cfc := cf.C.(Circuit)
	if cf.Set {
		for _, c := range cdb.circuits {
			if c != cfc {
				c.SetFlag(cf.Flag, &cf.Lspid, cf.Li)
			}
		}
	} else {
		for _, c := range cdb.circuits {
			if c != cfc {
				c.ClearFlag(cf.Flag, &cf.Lspid, cf.Li)
				continue
			}
		}
	}
}

func (cdb *CircuitDB) processFlags() {
	for {
		select {
		case cf := <-cdb.flagsC:
			cdb.processFlag(&cf)
		}
	}
}
