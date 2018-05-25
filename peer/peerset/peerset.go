package peerset

import (
	"p2p/peer"
	"sync"
)

// peerset是一个线程安全的节点集合
type PeerSet struct {
	ps   map[peer.ID]struct{}
	lock sync.Mutex
	size int
}

func New() *PeerSet {
	return &PeerSet{
		ps:   make(map[peer.ID]struct{}),
		size: -1,
	}
}

// NewLimited新生产一个固定数量的集合
func NewLimited(size int) *PeerSet {
	return &PeerSet{
		ps:   make(map[peer.ID]struct{}),
		size: size,
	}
}

// add 添加新的节点
func (ps *PeerSet) Add(p peer.ID) {
	ps.lock.Lock()
	defer ps.lock.Unlock()
	ps.ps[p] = struct{}{}
}

// contains 检查指定id是否在集合汇中
func (ps *PeerSet) Contains(p peer.ID) bool {
	ps.lock.Lock()
	defer ps.lock.Unlock()
	if _, ok := ps.ps[p]; ok {
		return true
	}
	return false
}

func (ps *PeerSet) Size() int {
	ps.lock.Lock()
	defer ps.lock.Unlock()
	return len(ps.ps)
}

// TryAdd: 添加的时候出现以下两种情况会添加失败
// 1)已经存在集合中
// 2)超过了集合设定的大小
func (ps *PeerSet) TryAdd(p peer.ID) bool {
	ps.lock.Lock()
	defer ps.lock.Unlock()
	if _, ok := ps.ps[p]; !ok && (len(ps.ps) < ps.size || ps.size == -1) {
		ps.ps[p] = struct{}{}
		return true
	}
	return false
}

// Pees 返回一个存放节点id的数组
func (ps *PeerSet) Peers() []peer.ID {
	ps.lock.Lock()
	defer ps.lock.Unlock()
	out := make([]peer.ID, 0, len(ps.ps))
	for k := range ps.ps {
		out = append(out, k)
	}
	return out
}
