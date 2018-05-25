package peerset

import (
	"p2p/peer"
	"sync"
	"testing"
)

func TestTryAdd(t *testing.T) {
	var p1 peer.ID = "123"
	var p2 peer.ID = "234"
	var p3 peer.ID = "235"
	ps := New()
	ps.Add(p1)
	l := ps.Size()
	if l != 1 {
		t.Errorf("集合长度为%d, 应该是%d", l, 1)
	}
	pl := NewLimited(2)
	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		pl.TryAdd(p1)
		wg.Done()
	}()
	go func() {
		pl.TryAdd(p2)
		wg.Done()
	}()
	go func() {
		pl.TryAdd(p3)
		wg.Done()
	}()
	wg.Wait()
	s := pl.Size()
	if s != 2 {
		t.Errorf("集合长度为%d, 应该为%d", s, 2)
	}
}
