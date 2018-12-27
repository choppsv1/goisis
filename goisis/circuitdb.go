// -*- coding: utf-8 -*-
//
// December 23 2018, Christian Hopps <chopps@gmail.com>

//
package main

import (
	"fmt"
	"github.com/choppsv1/goisis/clns"
	"github.com/choppsv1/goisis/goisis/update"
	// . "github.com/choppsv1/goisis/logging" // nolint
)

// CircuitDB is a database of circuits we run on.
type CircuitDB struct {
	circuits map[string]Circuit
	rpC      chan RPC
}

// NewCircuitDB allocate and initialize a new circuit database.
func NewCircuitDB() *CircuitDB {
	cdb := &CircuitDB{
		circuits: make(map[string]Circuit),
		rpC:      make(chan RPC),
	}

	go cdb.run()

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

// func (cdb *CircuitDB) yangData(name string) interface{} {
func (cdb *CircuitDB) yangData(name string) interface{} {
	var ifdata []*YangInterface
	if name == "" {
		for _, c := range cdb.circuits {
			yd, err := c.YangData()
			if err != nil {
				return err
			}
			ifdata = append(ifdata, yd)
		}
		return ifdata
	}

	c, ok := cdb.circuits[name]
	if !ok {
		return fmt.Errorf("Unknown interface %s", name)
	}

	yd, err := c.YangData()
	if err != nil {
		return err
	}
	return append(ifdata, yd)
}

// YangData returns the yang data for an interface
func (cdb *CircuitDB) YangData(key string) ([]*YangInterface, error) {
	i, err := DoRPC(cdb.rpC, func() interface{} { return cdb.yangData(key) })
	if err != nil {
		return nil, err
	}
	return i.([]*YangInterface), nil
}

// run handles creation/deletion of circuits as well as yang data requests
func (cdb *CircuitDB) run() {
	for {
		select {
		case in := <-cdb.rpC:
			in.Result <- in.F()
		}
	}
}
