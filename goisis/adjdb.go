package main

// import (
// 	"bytes"
// 	"fmt"
// 	"github.com/choppsv1/goisis/clns"
// 	"net"
// 	"sync"
// )

// //
// // AdjDB stores the adjacencies for a given level on a given link.
// //
// type AdjDB struct {
// 	l        clns.Level
// 	li       clns.LIndex
// 	link     Link
// 	lock     sync.Mutex
// 	snpaMap  map[[clns.SNPALen]byte]*Adj
// 	srcidMap map[[clns.SysIDLen]byte]*Adj
// }

// //
// // NewAdjDB creates and initializes a new adjacency database for a given link
// // and level.
// func NewAdjDB(link Link, li clns.LIndex) *AdjDB {
// 	return &AdjDB{
// 		l:        li.ToLevel(),
// 		li:       li,
// 		link:     link,
// 		snpaMap:  make(map[[clns.SNPALen]byte]*Adj),
// 		srcidMap: make(map[[clns.SysIDLen]byte]*Adj),
// 	}
// }

// func (db *AdjDB) String() string {
// 	return fmt.Sprintf("AdjDB(%s)", db.link)
// }

// //
// // hasUpAdj returns true if the DB contains any Up adjacencies
// //
// func (db *AdjDB) hasUpAdj() bool {
// 	db.lock.Lock()
// 	defer db.lock.Unlock()

// 	for _, a := range db.srcidMap {
// 		if a.State == AdjStateUp {
// 			return true
// 		}
// 	}
// 	return false
// }

// // hasUpAdjSNPA returns true if the DB contains any Up adjacencies
// func (db *AdjDB) hasUpAdjSNPA(snpa net.HardwareAddr) bool {
// 	db.lock.Lock()
// 	defer db.lock.Unlock()

// 	for _, a := range db.srcidMap {
// 		if a.State == AdjStateUp {
// 			if bytes.Equal(snpa, a.snpa[:]) {
// 				return true
// 			}
// 		}
// 	}
// 	return false
// }

// //
// // ExpireAdj removes the adjacency from the DB returns true if DIS election
// // should be rerun.
// //
// func (db *AdjDB) ExpireAdj(a *Adj) bool {
// 	db.lock.Lock()
// 	// If the adjacency was up then we need to rerun DIS election.
// 	rundis := a.State == AdjStateUp
// 	delete(db.snpaMap, a.snpa)
// 	delete(db.srcidMap, a.sysid)
// 	db.lock.Unlock()
// 	return rundis
// }
