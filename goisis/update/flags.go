//
// -*- coding: utf-8 -*-
//
// November 20 2018, Christian Hopps <chopps@gmail.com>
//
//
package update

import "github.com/choppsv1/goisis/clns"

// IS-IS flooding flags.
type SxxFlag uint8

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
	flag  SxxFlag     // flag to set or clear
	l     clns.LIndex // level index
	set   bool        // set or clear
	all   bool        // all or single link
	link  interface{} // if all then not this link otherwise this link only
	lspid clns.LSPID
}

//
// Used for managing flags
//

type FlagSet map[interface{}]struct{}

func NewFlagSet() FlagSet {
	return make(map[interface{}]struct{})
}

// Add key to set, return true if was set, false if newly set.
func (s FlagSet) Add(key interface{}) bool {
	if _, isSet := s[key]; !isSet {
		s[key] = struct{}{}
		return true
	}
	return false
}

// Remove key from set, return true if key was set, false if wasn't present.
func (s FlagSet) Remove(key interface{}) bool {
	if _, isSet := s[key]; isSet {
		delete(s, key)
		return true
	}
	return false
}

// Contains returns true if key is in set.
func (s FlagSet) Contains(key interface{}) bool {
	_, isSet := s[key]
	return isSet
}
