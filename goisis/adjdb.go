package main

import (
	"fmt"
	"github.com/choppsv1/goisis/clns"
	"github.com/choppsv1/goisis/tlv"
	"net"
	"sync"
)

// ---------------------------------------------------------------
// AdjDB stores the adjacencies for a given level on a given link.
// ---------------------------------------------------------------
type AdjDB struct {
	level    int
	lindex   int
	link     Link
	lock     sync.Mutex
	snpaMap  map[[clns.SNPALen]byte]*Adj
	srcidMap map[[clns.SysIDLen]byte]*Adj
}

// --------------------------------------------------------------------------
// NewAdjDB creates and initializes a new adjacency database for a given link
// and level.
// --------------------------------------------------------------------------
func NewAdjDB(link Link, level int) *AdjDB {
	db := new(AdjDB)
	db.level = level
	db.lindex = level - 1
	db.link = link
	db.snpaMap = make(map[[clns.SNPALen]byte]*Adj)
	db.srcidMap = make(map[[clns.SysIDLen]byte]*Adj)
	return db
}

func (db *AdjDB) String() string {
	return fmt.Sprintf("AdjDB(%s)", db.link)
}

// ---------------------------------------------------------------
// GetAdjSNPA returns an list of SNPA for all non-DOWN adjacencies
// ---------------------------------------------------------------
func (db *AdjDB) GetAdjSNPA() []net.HardwareAddr {
	db.lock.Lock()
	defer db.lock.Unlock()

	alist := make([]net.HardwareAddr, 0, len(db.srcidMap))
	for _, a := range db.srcidMap {
		if a.State == AdjStateDown {
			continue
		}
		alist = append(alist, a.snpa[:])
	}
	return alist
}

// -----------------------------------------------------------
// HasUpAdj returns true if the DB contains any Up adjacencies
// -----------------------------------------------------------
func (db *AdjDB) HasUpAdj() bool {
	db.lock.Lock()
	defer db.lock.Unlock()

	for _, a := range db.srcidMap {
		if a.State == AdjStateUp {
			return true
		}
	}
	return false
}

// ----------------------------------------------------------------------
// UpdateAdj creates or refreshes an existing adjacency, the return value
// indicates if DIS election should be [re]run.
// ----------------------------------------------------------------------
func (db *AdjDB) UpdateAdj(payload []byte, tlvs map[tlv.Type][]tlv.Data, src net.HardwareAddr) bool {
	db.lock.Lock()
	defer db.lock.Unlock()

	debug(DbgFAdj, "%s: UpdateAdj for %s", db, src)

	// XXX is there a better way to do 6 byte key values?
	var snpa [clns.SNPALen]byte
	var srcid [clns.SysIDLen]byte
	copy(snpa[:], src)
	off := clns.HdrCLNSSize + clns.HdrIIHLANSrcID
	copy(srcid[:], payload[off:off+clns.SysIDLen])

	a, ok := db.snpaMap[snpa]
	if !ok {
		// Create new adjacency
		a := NewAdj(db, snpa, srcid, payload, tlvs)
		db.snpaMap[snpa] = a
		db.srcidMap[srcid] = a
		// If the adjacency state is Up then we want to rerun DIS election
		return a.State == AdjStateUp
	}
	// If the system ID changed ignore and let timeout.
	if a.sysid != srcid {
		return false
	}
	return a.Update(payload, tlvs)
}

// ------------------------------------------------------------------------
// ExpireAdj removes the adjacency from the DB and triggers DIS election if
// needed.
// ------------------------------------------------------------------------
func (db *AdjDB) ExpireAdj(a *Adj) {
	var rundis bool

	func() {
		db.lock.Lock()
		defer db.lock.Unlock()
		// If the adjacency was up then we need to rerun DIS election.
		rundis = a.State == AdjStateUp
		delete(db.snpaMap, a.snpa)
		delete(db.srcidMap, a.sysid)
	}()

	if rundis {
		db.link.DISInfoChanged(db.level)
	}

}
