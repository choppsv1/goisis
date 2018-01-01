package time

import (
	"fmt"
	"time"
)

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
