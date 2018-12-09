package main

import (
	"fmt"
	"github.com/choppsv1/goisis/clns"
	"github.com/choppsv1/goisis/goisis/update"
	"net"
	"strings"
)

//
// CircuitDB is a database of circuits we run on.
//
type CircuitDB struct {
	circuits map[string]Circuit
	flagsC   chan update.ChgSxxFlag
}

// NewCircuitDB allocate and initialize a new circuit database.
func NewCircuitDB() *CircuitDB {
	cdb := &CircuitDB{
		circuits: make(map[string]Circuit),
		flagsC:   make(chan update.ChgSxxFlag, 10),
	}

	go cdb.processChgFlags()

	return cdb
}

// NewCircuit creates a circuit enabled for the given levels.
func (cdb *CircuitDB) NewCircuit(ifname string, lf clns.LevelFlag, updb [2]*update.DB) (*CircuitLAN, error) {
	ifname, err := resolveIfname(ifname)
	if err != nil {
		return nil, err
	}
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

func (cdb *CircuitDB) processChgFlag(cf *update.ChgSxxFlag) {
	cfc, _ := cf.C.(Circuit)
	if cf.Set {
		if !cf.All {
			cfc.SetFlag(cf.Flag, &cf.Lspid, cf.Li)
			return
		}
		for _, c := range cdb.circuits {
			if c != cfc {
				c.SetFlag(cf.Flag, &cf.Lspid, cf.Li)
			}
		}
	} else {
		if !cf.All {
			cfc.ClearFlag(cf.Flag, &cf.Lspid, cf.Li)
			return
		}
		for _, c := range cdb.circuits {
			if c != cfc {
				c.ClearFlag(cf.Flag, &cf.Lspid, cf.Li)
			}
		}
	}
}

func (cdb *CircuitDB) processChgFlags() {
	for {
		select {
		case cf := <-cdb.flagsC:
			cdb.processChgFlag(&cf)
		}
	}
}

func resolveIfname(in string) (string, error) {
	// First see if in arg is an address.

	intfs, err := net.Interfaces()
	if err != nil {
		return in, err
	}
	for _, intf := range intfs {
		if strings.EqualFold(in, intf.Name) {
			return intf.Name, nil
		}

		inAddr := net.ParseIP(in)
		if inAddr != nil {
			addrs, err := intf.Addrs()
			if err != nil {
				continue
			}
			for _, addr := range addrs {
				ipnet := addr.(*net.IPNet)
				if inAddr.Equal(ipnet.IP) {
					return intf.Name, nil
				}
				if ipnet.Contains(inAddr) {
					return intf.Name, nil
				}
			}
		}

		macAddr, err := net.ParseMAC(in)
		if macAddr != nil && err == nil {
			if strings.EqualFold(macAddr.String(), intf.HardwareAddr.String()) {
				return intf.Name, nil
			}
		}
	}
	return in, fmt.Errorf("Can't determine interface using string %s", in)
}
