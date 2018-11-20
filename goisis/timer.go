//
// -*- coding: utf-8 -*-
//
// November 20 2018, Christian Hopps <chopps@gmail.com>
//
//
package main

import (
	"time"
)

type HoldTimer struct {
	t   *time.Timer
	end time.Time
}

func NewHoldTimer(holdtime uint16, expireF func()) *HoldTimer {
	ns := time.Second * time.Duration(holdtime)
	return &HoldTimer{
		t:   time.AfterFunc(ns, expireF),
		end: time.Now().Add(ns),
	}
}

func (t *HoldTimer) Reset(holdtime uint16) bool {
	if !t.t.Stop() {
		return false
	}
	ns := time.Second * time.Duration(holdtime)
	t.end = time.Now().Add(ns)
	t.t.Reset(ns)
	return true
}

func (t *HoldTimer) Until() uint16 {
	if d := time.Until(t.end); d < 0 {
		return 0
	} else {
		return uint16(d / time.Second)
	}
}
