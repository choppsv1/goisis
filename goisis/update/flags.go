// -*- coding: utf-8 -*-
//
// November 20 2018, Christian Hopps <chopps@gmail.com>

// Package update implements the update process of the IS-IS routing protocol.
// This file contains code for implementing IS-IS flooding flags.
package update

import "github.com/choppsv1/goisis/clns"

// SxxFlag is an IS-IS flooding flag (but not a bit flag).
type SxxFlag uint8

// Values for SxxFlag
const (
	SRM SxxFlag = iota
	SSN
)

func (f SxxFlag) String() string {
	if f == SRM {
		return "SRM"
	} else if f == SSN {
		return "SSN"
	} else {
		panic("Bad Flag")
	}
}

// ChgSxxFlag is used for sending flag operations on channels.
type ChgSxxFlag struct {
	C     interface{} // if all then not this link otherwise this link only
	Lspid clns.LSPID
	Set   bool        // set or clear
	All   bool        // all or single link
	Flag  SxxFlag     // flag to set or clear
	Li    clns.Lindex // level index
}

//
// Flag owners
//

// FlagSet is the type used for tracking flags.
type FlagSet map[clns.LSPID]struct{}

// Add key to set, return true if was set, false if newly set.
func (s FlagSet) Add(lspid *clns.LSPID) bool {
	if _, isSet := s[*lspid]; !isSet {
		s[*lspid] = struct{}{}
		return true
	}
	return false
}

// Remove key from set, return true if key was set, false if wasn't present.
func (s FlagSet) Remove(lspid *clns.LSPID) bool {
	if _, isSet := s[*lspid]; isSet {
		delete(s, *lspid)
		return true
	}
	return false
}

// Contains returns true if key is in set.
func (s FlagSet) Contains(lspid *clns.LSPID) bool {
	_, isSet := s[*lspid]
	return isSet
}
