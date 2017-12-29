package main

import (
	"fmt"
	"time"
)

// Holdtime measures the amount of time left for some event.
type Holdtime struct {
	lifetime  time.Duration
	timestamp time.Time
}

func (ht *Holdtime) String() string {
	return fmt.Sprintf("Lifetime(left:%v, lifetime:%v",
		ht.TimeLeft(),
		ht.lifetime)
}

// NewLifetime initialize and return a new lifetime struct
func NewHoldtime(lifetime uint16) *Holdtime {
	ht := &Holdtime{
		lifetime:  time.Duration(lifetime) * time.Second,
		timestamp: time.Now(),
	}
	return ht
}

func (ht *Holdtime) Reset(lifetime uint16) {
	ht.lifetime = time.Duration(lifetime) * time.Second
	ht.timestamp = time.Now()
}

func (ht *Holdtime) ExpireAt() time.Time {
	return ht.timestamp.Add(ht.lifetime)
}

func (ht *Holdtime) TimeLeft() time.Duration {
	elapsed := time.Now().Sub(ht.timestamp)
	left := ht.lifetime - elapsed
	if left <= 0 {
		return 0
	}
	return left
}
