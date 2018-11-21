//
// -*- coding: utf-8 -*-
//
// November 20 2018, Christian Hopps <chopps@gmail.com>
//
//
package main

// //var set = struct{}{}

// type SxxFlag uint8

// const (
// 	SRM SxxFlag = iota
// 	SSN
// )

// func (f SxxFlag) String() string {
// 	if f == SRM {
// 		return "SRM"
// 	} else if f == SSN {
// 		return "SSN"
// 	} else {
// 		panic("Bad Flag")
// 	}
// }

// type FlagSet map[interface{}]struct{}

// func NewFlagSet() FlagSet {
// 	return make(map[interface{}]struct{})
// }

// // Add key to set, return true if was set, false if newly set.
// func (s FlagSet) Add(key interface{}) bool {
// 	if _, isSet := s[key]; !isSet {
// 		s[key] = struct{}{}
// 		return true
// 	}
// 	return false
// }

// // Remove key from set, return true if key was set, false if wasn't present.
// func (s FlagSet) Remove(key interface{}) bool {
// 	if _, isSet := s[key]; isSet {
// 		delete(s, key)
// 		return true
// 	}
// 	return false
// }

// // Contains returns true if key is in set.
// func (s FlagSet) Contains(key interface{}) bool {
// 	_, isSet := s[key]
// 	return isSet
// }
