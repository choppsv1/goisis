// -*- coding: utf-8 -*-
//
// December 21 2018, Christian Hopps <chopps@gmail.com>

//
package main

import (
	"encoding/json"
	"fmt"
	"github.com/choppsv1/goisis/clns"
	"github.com/choppsv1/goisis/goisis/update"
	"github.com/gorilla/mux"
	"io"
	"net/http"
)

// IFList is a yang list of interfaces
type IFList struct {
	Ifs []*YangInterface `json:"interface,omitempty"`
}

// YangRoot is the root of the yang module.
type YangRoot struct {
	Enable    bool           `json:"enable"`
	LevelType clns.LevelFlag `json:"level-type"`
	SystemID  clns.SystemID  `json:"system-id"`
	//...
	Interfaces IFList `json:"interfaces,omitempty"`
}

func errToHTTP(w http.ResponseWriter, err error) {
	http.Error(w, err.Error(), http.StatusInternalServerError)
}

func muxRoot(w http.ResponseWriter, r *http.Request, cdb *CircuitDB) {
	w.WriteHeader(http.StatusOK)

	root := YangRoot{
		Enable:     true,
		LevelType:  GlbISType,
		SystemID:   GlbSystemID,
		Interfaces: IFList{interfaceData(w, nil, cdb)},
	}

	jvars, err := json.Marshal(root)
	if err != nil {
		errToHTTP(w, err)
		return
	}
	if _, err = io.WriteString(w, string(jvars)); err != nil {
		errToHTTP(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

//              +--rw lsp-pacing-interval? rt-types:timer-value-milliseconds
//              +--rw lsp-retransmit-interval? rt-types:timer-value-seconds16
//              +--rw passive?                   boolean
//              +--rw csnp-interval? rt-types:timer-value-seconds16
//              +--rw hello-padding
//              |  +--rw enable?   boolean
//              +--rw mesh-group-enable?         mesh-group-state
//              +--rw mesh-group?                uint8
//              +--rw interface-type?            interface-type
//              +--rw enable?                    boolean {admin-control}?
//              +--rw tag*                       uint32 {prefix-tag}?
//              +--rw tag64*                     uint64 {prefix-tag64}?
//              +--rw node-flag?                 boolean {node-flag}?
//              +--rw hello-authentication
//              |  +--rw (authentication-type)?
//              |  |  +--:(key-chain) {key-chain}?
//              |  |  |  +--rw key-chain?          key-chain:key-chain-ref
//              |  |  +--:(password)
//              |  |     +--rw key?                string
//              |  |     +--rw crypto-algorithm?   identityref
//              |  +--rw level-1
//              |  |  +--rw (authentication-type)?
//              |  |     +--:(key-chain) {key-chain}?
//              |  |     |  +--rw key-chain? key-chain:key-chain-ref
//              |  |     +--:(password)
//              |  |        +--rw key?                string
//              |  |        +--rw crypto-algorithm?   identityref
//              |  +--rw level-2
//              |     +--rw (authentication-type)?
//              |        +--:(key-chain) {key-chain}?
//              |        |  +--rw key-chain? key-chain:key-chain-ref
//              |        +--:(password)
//              |           +--rw key?                string
//              |           +--rw crypto-algorithm?   identityref
//              +--rw hello-interval
//              |  +--rw value?     rt-types:timer-value-seconds16
//              |  +--rw level-1
//              |  |  +--rw value?   rt-types:timer-value-seconds16
//              |  +--rw level-2
//              |     +--rw value?   rt-types:timer-value-seconds16
//              +--rw hello-multiplier
//              |  +--rw value?     uint16
//              |  +--rw level-1
//              |  |  +--rw value?   uint16
//              |  +--rw level-2
//              |     +--rw value?   uint16
//              +--rw priority
//              |  +--rw value?     uint8
//              |  +--rw level-1
//              |  |  +--rw value?   uint8
//              |  +--rw level-2
//              |     +--rw value?   uint8
//              +--rw metric
//              |  +--rw value?     wide-metric
//              |  +--rw level-1
//              |  |  +--rw value?   wide-metric
//              |  +--rw level-2
//              |     +--rw value?   wide-metric
//              +--rw bfd {bfd}?
//              |  +--rw enable?                           boolean
//              |  +--rw local-multiplier?                 multiplier
//              |  +--rw (interval-config-type)?
//              |     +--:(tx-rx-intervals)
//              |     |  +--rw desired-min-tx-interval?    uint32
//              |     |  +--rw required-min-rx-interval?   uint32
//              |     +--:(single-interval) {single-minimum-interval}?
//              |        +--rw min-interval?               uint32
//              +--rw address-families {nlpid-control}?
//              |  +--rw address-family-list* [address-family]
//              |     +--rw address-family    iana-rt-types:address-family
//              +--rw mpls
//              |  +--rw ldp
//              |     +--rw igp-sync?   boolean {ldp-igp-sync}?
//              +--rw fast-reroute {fast-reroute}?
//              |  +--rw lfa {lfa}?
//              |     +--rw candidate-enable?   boolean
//              |     +--rw enable?             boolean
//              |     +--rw remote-lfa {remote-lfa}?
//              |     |  +--rw enable?   boolean
//              |     +--rw level-1
//              |     |  +--rw candidate-enable?   boolean
//              |     |  +--rw enable?             boolean
//              |     |  +--rw remote-lfa {remote-lfa}?
//              |     |     +--rw enable?   boolean
//              |     +--rw level-2
//              |        +--rw candidate-enable?   boolean
//              |        +--rw enable?             boolean
//              |        +--rw remote-lfa {remote-lfa}?
//              |           +--rw enable?   boolean
//              +--ro adjacencies
//              |  +--ro adjacency* []
//              |     +--ro neighbor-sys-type?              level
//              |     +--ro neighbor-sysid?                 system-id
//              |     +--ro neighbor-extended-circuit-id? extended-circuit-id
//              |     +--ro neighbor-snpa?                  snpa
//              |     +--ro usage?                          level
//              |     +--ro hold-timer? rt-types:timer-value-seconds16
//              |     +--ro neighbor-priority?              uint8
//              |     +--ro lastuptime?                     yang:timestamp
//              |     +--ro state?                          adj-state-type
//              +--ro event-counters
//              |  +--ro adjacency-changes?             uint32
//              |  +--ro adjacency-number?              uint32
//              |  +--ro init-fails?                    uint32
//              |  +--ro adjacency-rejects?             uint32
//              |  +--ro id-len-mismatch?               uint32
//              |  +--ro max-area-addresses-mismatch?   uint32
//              |  +--ro authentication-type-fails?     uint32
//              |  +--ro authentication-fails?          uint32
//              |  +--ro lan-dis-changes?               uint32
//              +--ro packet-counters
//              |  +--ro level* [level]
//              |     +--ro level      level-number
//              |     +--ro iih
//              |     |  +--ro in?    uint32
//              |     |  +--ro out?   uint32
//              |     +--ro ish
//              |     |  +--ro in?    uint32
//              |     |  +--ro out?   uint32
//              |     +--ro esh
//              |     |  +--ro in?    uint32
//              |     |  +--ro out?   uint32
//              |     +--ro lsp
//              |     |  +--ro in?    uint32
//              |     |  +--ro out?   uint32
//              |     +--ro psnp
//              |     |  +--ro in?    uint32
//              |     |  +--ro out?   uint32
//              |     +--ro csnp
//              |     |  +--ro in?    uint32
//              |     |  +--ro out?   uint32
//              |     +--ro unknown
//              |        +--ro in?    uint32
//              |        +--ro out?   uint32
//              +--rw topologies {multi-topology}?
//                 +--rw topology* [name]
//                    +--rw name      ->
// ../../../../../../../../rt:ribs/rib/name
//                    +--rw metric
//                       +--rw value?     wide-metric
//                       +--rw level-1
//                       |  +--rw value?   wide-metric
//                       +--rw level-2
//                          +--rw value?   wide-metric

// YangAdj is the adjacency data for the yang model
type YangAdj struct {
	Istype clns.LevelFlag `json:"neighbor-sys-type"` //level
	Sysid  clns.SystemID  `json:"neighbor-sysid"`    //system-id
	// ExtCID   uint8          `json:"neighbor-extended-circuit-id"` // extended-circuit-id
	Snpa     clns.SNPA      `json:"neighbor-snpa"`     //                  snpa
	State    AdjState       `json:"state"`             //                          adj-state-type
	Priority uint8          `json:"neighbor-priority"` //              uint8
	Usage    clns.LevelFlag `json:"usage"`             //                          level
	//`json:"hold-timer"` // rt-types:timer-value-seconds16
	// `json:"lastuptime"` //                     yang:timestamp
}

// YangData returns the yang data for an adjacency
func (a *Adj) YangData() *YangAdj {
	yd := &YangAdj{
		Istype:   a.ctype,
		Sysid:    a.sysid,
		Snpa:     a.snpa,
		State:    a.state,
		Priority: a.priority,
		Usage:    a.usage,
	}
	return yd
}

type Value struct {
	Value uint `json:"value,omitempty"`
}

type LevValue struct {
	*Value
	Level1 *Value `json:"level-1,omitempty"`
	Level2 *Value `json:"level-2,omitempty"`
}

// YangInterface is the interface data for the yang model
type YangInterface struct {
	Name       string         `json:"name"`
	LevelType  clns.LevelFlag `json:"level-type"`
	HelloInt   LevValue       `json:"hello-interval"`
	HelloMult  LevValue       `json:"hello-multiplier"`
	Priority   LevValue       `json:"priority"`
	Metric     LevValue       `json:"metric"`
	Adjcencies struct {
		Adj []*YangAdj `json:"adjacency"`
	} `json:"adjcencies"`
}

// YangData returns the yang data for an interface
func (c *CircuitLAN) YangData() *YangInterface {
	yd := &YangInterface{
		Name:      c.intf.Name,
		LevelType: c.lf,
		// HelloInt: {
		// 	Value:
		// }
	}
	for _, levlink := range c.levlink {
		if levlink == nil {
			continue
		}
		if levlink.l == 1 {
			yd.HelloInt.Level1 = &Value{Value: levlink.helloInt}
			yd.HelloMult.Level1 = &Value{Value: levlink.holdMult}
			yd.Priority.Level1 = &Value{Value: uint(levlink.priority)}
			yd.Metric.Level1 = &Value{Value: uint(levlink.metric)}
		} else {
			yd.HelloInt.Level2 = &Value{Value: levlink.helloInt}
			yd.HelloMult.Level2 = &Value{Value: levlink.holdMult}
			yd.Priority.Level2 = &Value{Value: uint(levlink.priority)}
			yd.Metric.Level2 = &Value{Value: uint(levlink.metric)}
		}
		for _, a := range levlink.srcidMap {
			yd.Adjcencies.Adj = append(yd.Adjcencies.Adj, a.YangData())
		}
	}
	return yd
}

func interfaceData(w http.ResponseWriter, name *string, cdb *CircuitDB) []*YangInterface {
	var ifdata []*YangInterface
	if name != nil {
		c, ok := cdb.circuits[*name]
		if !ok {
			errToHTTP(w, fmt.Errorf("No interface named %s", *name))
			return nil
		}
		ifdata = append(ifdata, c.YangData())
	} else {
		for _, c := range cdb.circuits {
			ifdata = append(ifdata, c.YangData())
		}
	}
	return ifdata
}

func muxIntfs(w http.ResponseWriter, r *http.Request, cdb *CircuitDB) {
	w.WriteHeader(http.StatusOK)
	vars := mux.Vars(r)

	var ifdata []*YangInterface
	name, ok := vars["name"]
	if !ok {
		ifdata = interfaceData(w, &name, cdb)
	} else {
		ifdata = interfaceData(w, nil, cdb)
	}
	jvars, err := json.Marshal(ifdata)
	if err != nil {
		errToHTTP(w, err)
		return
	}

	_, err = io.WriteString(w, string(jvars))
	if err != nil {
		errToHTTP(w, err)
	}
}

// SetupManagement initializes the management interface.
func SetupManagement(cdb *CircuitDB, updb [2]*update.DB) error {
	rootF := func(w http.ResponseWriter, r *http.Request) {
		muxRoot(w, r, cdb)
	}
	intfF := func(w http.ResponseWriter, r *http.Request) {
		muxIntfs(w, r, cdb)
	}
	r := mux.NewRouter()
	r.HandleFunc("/isis", rootF)
	r.HandleFunc("/isis/interfaces", intfF)
	r.HandleFunc("/isis/interfaces/interface", intfF)
	r.HandleFunc("/isis/interfaces/interface={name}", intfF)
	// r.HandleFunc("/system-id")

	return http.ListenAndServe("localhost:8080", r)
}
