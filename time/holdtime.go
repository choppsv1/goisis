package time

import (
	"fmt"
	"time"
)

// HoldTimer opaque values for the hold timer.
type HoldTimer struct {
	t   *time.Timer
	end time.Time
}

// NewHoldTimer creates a new hold timer.
func NewHoldTimer(holdtime uint16, expireF func()) *HoldTimer {
	ns := time.Second * time.Duration(holdtime)
	return &HoldTimer{
		t:   time.AfterFunc(ns, expireF),
		end: time.Now().Add(ns),
	}
}

// Stop stops the hold timer if it can, if not it returns false.
func (t *HoldTimer) Stop() bool {
	return t.t.Stop()
}

// Reset resets the timer if possible, if it has already fired then false is
// returned.
func (t *HoldTimer) Reset(holdtime uint16) bool {

	// XXX It's very important that Stop either be called prior or we know
	// its expired before resetting here. Just calling t.t.Stop() here will
	// return false if it doesn't stop the timer (i.e., if it expired or we
	// already stopped it. Since we almost always want to Stop externally
	// (or we know it expired) just require this always.
	// if !t.t.Stop() {
	//      // The timer has fire the function has is is being called.
	//      return false
	// }

	ns := time.Second * time.Duration(holdtime)
	t.end = time.Now().Add(ns)
	t.t.Reset(ns)
	return true
}

// Until returns the number of seconds until the timer will fire.
func (t *HoldTimer) Until() uint16 {
	if d := time.Until(t.end); d < 0 {
		return 0
	} else {
		return uint16(d / time.Second)
	}
}

//
// We don't use this.
//

// Timeout measures the amount of time left for some event. It can be thought of
// as a passive timer.
type Timeout struct {
	duration  time.Duration
	timestamp time.Time
}

func (ht *Timeout) String() string {
	return fmt.Sprintf("Timeout(left:%v, duration:%v",
		ht.Remaining(),
		ht.duration)
}

// NewTimeoutSec get a new timeout struct with a given duration
func NewTimeout(duration time.Duration) *Timeout {
	ht := &Timeout{
		duration:  duration,
		timestamp: time.Now(),
	}
	return ht
}

// NewTimeoutSec get a new timeout struct with a duration specified in seconds. The
// precision of the timeout value is still based on base time.Duration
func NewTimeoutSec(seconds int) *Timeout {
	ht := &Timeout{
		duration:  time.Duration(seconds) * time.Second,
		timestamp: time.Now(),
	}
	return ht
}

// Reset resets the timeout value to the new duration.
func (ht *Timeout) Reset(duration time.Duration) {
	ht.duration = time.Duration(duration) * time.Second
	ht.timestamp = time.Now()
}

// ResetSec resets the timeout value to the new number of seconds.
func (ht *Timeout) ResetSec(seconds int) {
	ht.duration = time.Duration(seconds) * time.Second
	ht.timestamp = time.Now()
}

// ExpiresAt returns the time.Time at which this timeout expires.
func (ht *Timeout) ExpiresAt() time.Time {
	return ht.timestamp.Add(ht.duration)
}

// IsExpired returns true if the timeout has expired.
func (ht *Timeout) IsExpired() bool {
	return ht.Remaining() <= 0
}

// Remaining returns the duration left before the timeout expires.
func (ht *Timeout) Remaining() time.Duration {
	elapsed := time.Now().Sub(ht.timestamp)
	left := ht.duration - elapsed
	if left <= 0 {
		return 0
	}
	return left
}

// RemainingSec returns the number of seconds left before the timeout expires.
func (ht *Timeout) RemainingSec() int {
	elapsed := time.Now().Sub(ht.timestamp)
	left := int((ht.duration - elapsed) / time.Second)
	if left <= 0 {
		return 0
	}
	return left
}
