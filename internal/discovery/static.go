package discovery

import (
	"context"
	"sync"
)

// Static is an in-process Discovery used by tests and the --no-mdns path. It is
// channel-based and race-clean because it is exercised under -race in every
// integration test. Pre-seeded hints are re-announced on each Browse so a node
// started after its peer still learns it.
type Static struct {
	mu    sync.Mutex
	hints []PeerHint
	// subs are live browse subscriptions to fan Push out to.
	subs map[chan PeerHint]struct{}
}

// NewStatic returns a Static seeded with the given hints.
func NewStatic(seed ...PeerHint) *Static {
	return &Static{hints: append([]PeerHint(nil), seed...), subs: make(map[chan PeerHint]struct{})}
}

// Advertise is a no-op for the static discovery (peers are injected directly).
func (s *Static) Advertise(ctx context.Context, self Self) error {
	<-ctx.Done()
	return nil
}

// Browse returns a channel pre-loaded with the seeded hints and fed by any
// later Push, closed when ctx is canceled.
func (s *Static) Browse(ctx context.Context) (<-chan PeerHint, error) {
	ch := make(chan PeerHint, 16)

	s.mu.Lock()
	seeded := append([]PeerHint(nil), s.hints...)
	s.subs[ch] = struct{}{}
	s.mu.Unlock()

	go func() {
		for _, h := range seeded {
			select {
			case ch <- h:
			case <-ctx.Done():
				s.removeSub(ch)
				close(ch)
				return
			}
		}
		<-ctx.Done()
		s.removeSub(ch)
		close(ch)
	}()
	return ch, nil
}

func (s *Static) removeSub(ch chan PeerHint) {
	s.mu.Lock()
	delete(s.subs, ch)
	s.mu.Unlock()
}

// Push delivers a hint to all live Browse subscribers (and records it so later
// Browse calls re-announce it).
func (s *Static) Push(h PeerHint) {
	s.mu.Lock()
	s.hints = append(s.hints, h)
	subs := make([]chan PeerHint, 0, len(s.subs))
	for ch := range s.subs {
		subs = append(subs, ch)
	}
	s.mu.Unlock()
	for _, ch := range subs {
		select {
		case ch <- h:
		default:
		}
	}
}

// Close is a no-op.
func (s *Static) Close() error { return nil }
