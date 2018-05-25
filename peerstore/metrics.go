package peerstore

import (
	"p2p/peer"
	"sync"
	"time"
)

var LatencyEWMASmoothing = 0.1

type Metrics interface {
	RecordLatency(id peer.ID, duration time.Duration)
	LatencyEWMA(id peer.ID) time.Duration
}

type metrics struct {
	latmap map[peer.ID]time.Duration
	lock   sync.RWMutex
}

func NewMetrics() *metrics {
	return &metrics{
		latmap: make(map[peer.ID]time.Duration),
	}
}

func (m *metrics) RecordLatency(p peer.ID, next time.Duration) {
	nextf := float64(next)
	s := LatencyEWMASmoothing
	if s > 1 || s < 0 {
		s = 0.1 // ignore the knob. it's broken. look, it jiggles.
	}

	m.lock.Lock()
	ewma, found := m.latmap[p]
	ewmaf := float64(ewma)
	if !found {
		m.latmap[p] = next // when no data, just take it as the mean.
	} else {
		nextf = ((1.0 - s) * ewmaf) + (s * nextf)
		m.latmap[p] = time.Duration(nextf)
	}
	m.lock.Unlock()
}

// LatencyEWMA returns an exponentially-weighted moving avg.
// of all measurements of a peer's latency.
func (m *metrics) LatencyEWMA(p peer.ID) time.Duration {
	m.lock.RLock()
	lat := m.latmap[p]
	m.lock.RUnlock()
	return time.Duration(lat)
}
