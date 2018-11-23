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
	dis      [2][256]bool
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

// GetFlagsC returns the flags channel for this circuit DB.
func (cdb *CircuitDB) GetFlagsC() chan<- update.ChgSxxFlag {
	return cdb.flagsC
}

// SetDIS updates whether we are DIS on the circuit (LAN) ID for the level.
func (cdb *CircuitDB) SetDIS(li clns.LIndex, uint8 cid, isDis bool) {
	// XXX no lock! Fix this to not need one, called from link hello go routine
	cdb.dis[li][cid] = isDis
}

// IsDIS checks whether we are DIS on the circuit (LAN) ID for the level.
func (cdb *CircuitDB) IsDIS(li clns.LIndex, uint8 cid) bool {
	// XXX no lock! Fix this to not need one, called from update process.
	return cdb.dis[li][cid]
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
	if cf.Set {
		for _, c := range cdb.circuits {
			if c != cf.Link {
				c.SetFlag(cf.Flag, &cf.Lspid, cf.Li)
			}
		}
	} else {
		for _, c := range cdb.circuits {
			if c != cf.Link {
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
