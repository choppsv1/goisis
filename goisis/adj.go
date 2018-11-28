package main

import (
	"bytes"
	"fmt"
	"github.com/choppsv1/goisis/clns"
	"github.com/choppsv1/goisis/pkt"
	"github.com/choppsv1/goisis/tlv"
	"time"
)

//
// AdjState represents the state of the IS-IS adjcency
//
type AdjState int

//
// AdjState constants for the state of the IS-IS adjcency
//
const (
	AdjStateDown AdjState = iota
	AdjStateInit
	AdjStateUp
)

var stateStrings = map[AdjState]string{
	AdjStateDown: "AdjStateUp",
	AdjStateInit: "AdjStateInit",
	AdjStateUp:   "AdjStateUp",
}

func (s AdjState) String() string {
	ss, ok := stateStrings[s]
	if !ok {
		return fmt.Sprintf("Unknown AdjState(%d)", s)
	}
	return ss
}

//
// Adj represents an IS-IS adjacency
//
type Adj struct {
	State     AdjState
	snpa      clns.SNPA // XXX need to conditionalize this for P2P.
	sysid     clns.SystemID
	lanID     clns.NodeID
	areas     [][]byte
	lf        clns.LevelFlag //  need to change this to LevelFlag for p2p
	priority  uint8
	hold      uint16
	holdTimer *time.Timer
	link      Link
}

func (a *Adj) String() string {
	return fmt.Sprintf("Adj(%s on %s)", clns.ISOString(a.sysid[:], false), a.link)
}

//
// NewAdj creates and initializes a new adjacency.
//
func NewAdj(link Link, snpa [clns.SNPALen]byte, srcid [clns.SysIDLen]byte, payload []byte, tlvs map[tlv.Type][]tlv.Data) *Adj {
	a := &Adj{
		link:  link,
		State: AdjStateDown,
		sysid: srcid,
	}
	if payload[clns.HdrCLNSPDUType] != clns.PDUTypeIIHP2P {
		iih := payload[clns.HdrCLNSSize:]
		a.snpa = snpa
		copy(a.lanID[:], iih[clns.HdrIIHLANLANID:])
	}
	debug(DbgFAdj, "NewAdj %s", a)

	// Update will finish the initialization
	a.Update(payload, tlvs)

	return a
}

// Update updates the adjacency with the information from the IIH, returns true
// if DIS election should be re-run.
func (a *Adj) Update(payload []byte, tlvs map[tlv.Type][]tlv.Data) bool {
	rundis := false
	iihp := payload[clns.HdrCLNSSize:]

	if payload[clns.HdrCLNSPDUType] != clns.PDUTypeIIHP2P {
		ppri := iihp[clns.HdrIIHLANPriority]
		if ppri != a.priority {
			a.priority = ppri
			rundis = true
		}
	}

	if a.lf.IsLevelEnabled(1) {
		// Update Areas
		areas, err := tlvs[tlv.TypeAreaAddrs][0].AreaAddrsValue()
		if err != nil {
			logger.Printf("ERROR: processing Area Address TLV from %s: %s", a, err)
			return true
		}
		a.areas = areas
	}

	if a.holdTimer != nil && !a.holdTimer.Stop() {
		debug(DbgFAdj, "%s failed to stop hold timer in time, letting expire", a)
		return false
	}

	oldstate := a.State
	a.State = AdjStateInit

	if a.link.IsP2P() {
		// XXX writeme
	} else {
		ourSNPA := a.link.GetOurSNPA()
	forloop:
		// Walk neighbor TLVs if we see ourselves mark adjacency Up.
		for _, ntlv := range tlvs[tlv.TypeISNeighbors] {
			addrs, err := ntlv.ISNeighborsValue()
			if err != nil {
				logger.Printf("ERROR: processing IS Neighbors TLV from %s: %v", a, err)
				break
			}
			for _, snpa := range addrs {
				if bytes.Equal(snpa, ourSNPA) {
					a.State = AdjStateUp
					break forloop
				}
			}
		}
	}

	if a.State != oldstate {
		if a.State == AdjStateUp {
			rundis = true
			logger.Printf("TRAP: AdjacencyStateChange: Up: %s", a)
		} else if oldstate == AdjStateUp {
			rundis = true
			logger.Printf("TRAP: AdjacencyStateChange: Down: %s", a)
		}
		debug(DbgFAdj, "New state %s for %s", a.State, a)
	}

	// Restart the hold timer.
	a.hold = pkt.GetUInt16(iihp[clns.HdrIIHHoldTime:])
	if a.holdTimer == nil {
		a.holdTimer = time.AfterFunc(time.Second*time.Duration(a.hold),
			func() {
				sysid := a.sysid
				a.link.ExpireAdj(sysid)
			})
	} else {
		a.holdTimer.Reset(time.Second * time.Duration(a.hold))
	}
	return rundis
}
