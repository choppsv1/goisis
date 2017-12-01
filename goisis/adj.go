package main

import (
	"fmt"
	"github.com/choppsv1/goisis/clns"
	"github.com/choppsv1/goisis/pkt"
	"github.com/choppsv1/goisis/tlv"
	"time"
)

// AdjState represents the state of the IS-IS adjcency
type AdjState int

// AdjState constants for the state of the IS-IS adjcency
const (
	AdjStateDown AdjState = iota
	AdjStateInit
	AdjStateUp
)

// Adj represents an IS-IS adjacency
type Adj struct {
	State     AdjState
	snpa      [clns.SNPALen]byte // XXX need to conditionalize this for P2P.
	sysid     [clns.SysIDLen]byte
	lanid     [clns.LANIDLen]byte
	areas     [][]byte
	db        *AdjDB
	level     int //  need to change this to circtype for p2p
	lindex    int
	priority  uint8
	hold      uint16
	holdTimer *time.Timer
}

func (a *Adj) String() string {
	return fmt.Sprintf("Adj(%s on %s)", clns.ISOString(a.sysid[:], false), a.db.link)
}

// NewAdj creates and initializes a new adjacency.
func NewAdj(db *AdjDB, snpa [clns.SNPALen]byte, srcid [clns.SysIDLen]byte, payload []byte, tlvs map[tlv.Type][]tlv.Data) *Adj {
	a := &Adj{
		State:  AdjStateDown,
		sysid:  srcid,
		db:     db,
		level:  db.level,
		lindex: db.lindex,
	}
	if payload[clns.HdrCLNSPDUType] != clns.PDUTypeIIHP2P {
		iih := payload[clns.HdrCLNSSize:]
		a.snpa = snpa
		copy(a.lanid[:], iih[clns.HdrIIHLANLANID:])
	}

	// Update will finish the initialization
	a.Update(payload, tlvs)

	return a
}

// Update updates the adjacency with the information from the IIH, returns true
// of DIS election should be re-run.
func (a *Adj) Update(payload []byte, tlvs map[tlv.Type][]tlv.Data) bool {
	rundis := false
	iihp := payload[clns.HdrCLNSSize:]

	// Reset the hold timer first.
	a.hold = pkt.GetUInt16(iihp[clns.HdrIIHHoldTime:])
	if a.holdTimer == nil {
		a.holdTimer = time.AfterFunc(time.Second*time.Duration(a.hold),
			func() {
				a.db.ExpireAdj(a)
			})
	} else if !a.holdTimer.Reset(time.Second * time.Duration(a.hold)) {
		// Our function has already been called so we will expire.
		return false
	}

	if payload[clns.HdrCLNSPDUType] != clns.PDUTypeIIHP2P {
		ppri := iihp[clns.HdrIIHLANPriority]
		if ppri != a.priority {
			a.priority = ppri
			rundis = true
		}
	}

	if a.lindex == 0 {
		// Update Areas
	}

	oldstate := a.State
	a.State = AdjStateInit
	// Walk neighbor TLVs if we see ourselves mark adjacency Up.
	// XXX write me

	if a.State != oldstate {
		if a.State == AdjStateUp {
			rundis = true
			logger.Printf("TRAP: AdjacencyStateChange: Up: %s", a)
		} else if oldstate == AdjStateUp {
			rundis = true
			logger.Printf("TRAP: AdjacencyStateChange: Down: %s", a)
		}
	}
	return rundis
}
