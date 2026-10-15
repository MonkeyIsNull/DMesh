// Package clock abstracts time so the handshake retransmit state machine can be
// driven deterministically in tests. The real implementation delegates to the
// standard library; the fake is manually advanced, so retransmit tests never
// sleep on the wall clock.
package clock

import (
	"sort"
	"sync"
	"time"
)

// Clock is the minimal time interface the transport depends on.
type Clock interface {
	// Now returns the current time.
	Now() time.Time
	// After returns a channel that receives once after d elapses.
	After(d time.Duration) <-chan time.Time
	// NewTimer returns a timer that fires once after d.
	NewTimer(d time.Duration) Timer
}

// Timer is a one-shot timer whose channel delivers a tick when it fires.
type Timer interface {
	C() <-chan time.Time
	// Stop prevents the timer from firing; it reports whether it was still
	// pending.
	Stop() bool
	// Reset restarts the timer for d; it reports whether it was still pending.
	Reset(d time.Duration) bool
}

// Real is the production clock backed by the time package.
type Real struct{}

// Now implements Clock.
func (Real) Now() time.Time { return time.Now() }

// After implements Clock.
func (Real) After(d time.Duration) <-chan time.Time { return time.After(d) }

// NewTimer implements Clock.
func (Real) NewTimer(d time.Duration) Timer { return &realTimer{t: time.NewTimer(d)} }

type realTimer struct{ t *time.Timer }

func (r *realTimer) C() <-chan time.Time        { return r.t.C }
func (r *realTimer) Stop() bool                 { return r.t.Stop() }
func (r *realTimer) Reset(d time.Duration) bool { return r.t.Reset(d) }

// Fake is a manually-advanced clock for deterministic tests. All pending timers
// whose deadline is at or before the advanced-to time fire in order.
type Fake struct {
	mu      sync.Mutex
	now     time.Time
	pending []*fakeTimer
}

// NewFake returns a Fake starting at the given time.
func NewFake(start time.Time) *Fake { return &Fake{now: start} }

// Now implements Clock.
func (f *Fake) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

// After implements Clock.
func (f *Fake) After(d time.Duration) <-chan time.Time {
	return f.NewTimer(d).C()
}

// NewTimer implements Clock.
func (f *Fake) NewTimer(d time.Duration) Timer {
	f.mu.Lock()
	defer f.mu.Unlock()
	t := &fakeTimer{
		ch:       make(chan time.Time, 1),
		deadline: f.now.Add(d),
		f:        f,
	}
	f.pending = append(f.pending, t)
	return t
}

// Advance moves the clock forward by d, firing every timer whose deadline falls
// within the interval (in deadline order).
func (f *Fake) Advance(d time.Duration) {
	f.mu.Lock()
	target := f.now.Add(d)
	f.now = target

	var due []*fakeTimer
	remaining := f.pending[:0]
	for _, t := range f.pending {
		if !t.stopped && !t.deadline.After(target) {
			due = append(due, t)
		} else if !t.stopped {
			remaining = append(remaining, t)
		}
	}
	f.pending = remaining
	f.mu.Unlock()

	sort.Slice(due, func(i, j int) bool { return due[i].deadline.Before(due[j].deadline) })
	for _, t := range due {
		select {
		case t.ch <- t.deadline:
		default:
		}
	}
}

type fakeTimer struct {
	ch       chan time.Time
	deadline time.Time
	stopped  bool
	f        *Fake
}

func (t *fakeTimer) C() <-chan time.Time { return t.ch }

func (t *fakeTimer) Stop() bool {
	t.f.mu.Lock()
	defer t.f.mu.Unlock()
	was := !t.stopped
	t.stopped = true
	return was
}

func (t *fakeTimer) Reset(d time.Duration) bool {
	t.f.mu.Lock()
	defer t.f.mu.Unlock()
	was := !t.stopped
	t.stopped = false
	t.deadline = t.f.now.Add(d)
	// Ensure the timer is tracked again if it had been removed.
	found := false
	for _, p := range t.f.pending {
		if p == t {
			found = true
			break
		}
	}
	if !found {
		t.f.pending = append(t.f.pending, t)
	}
	return was
}
