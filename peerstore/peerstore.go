package peerstore

import (
	"errors"
	ic "p2p/crypto"
	"p2p/peer"
	"sync"
)

// KeepBook 用于查找每个节点的公钥
type KeyBook interface {
	PubKey(peer.ID) ic.PubKey
	AddPubKey(peer.ID, ic.PubKey) error

	Private(peer.ID) ic.PrivKey
	AddPrivKey(peer.ID, ic.PrivKey) error
}

type keybook struct {
	pks map[peer.ID]ic.PubKey
	sks map[peer.ID]ic.PrivKey

	sync.RWMutex
}

func newKeyBook() *keybook {
	return &keybook{
		pks: map[peer.ID]ic.PubKey{},
		sks: map[peer.ID]ic.PrivKey{},
	}
}

func (kb *keybook) Peers() []peer.ID {
	kb.RLock()
	defer kb.RUnlock()
	ps := make([]peer.ID, 0)
	for p := range kb.pks {
		ps = append(ps, p)
	}
	for p := range kb.pks {
		if _, ok := kb.pks[p]; !ok {
			ps = append(ps, p)
		}
	}
	return ps
}

func (kb *keybook) PubKey(p peer.ID) ic.PubKey {
	kb.RLock()
	pk := kb.pks[p]
	kb.RUnlock()
	if pk != nil {
		return pk
	}
	pk, err := p.ExtractPublicKey()
	if err == nil && pk != nil {
		kb.Lock()
		kb.pks[p] = pk
		kb.Unlock()
	}
	return pk
}

func (kb *keybook) AddPubKey(id peer.ID, key ic.PubKey) error {
	if !id.MatchesPublicKey(key) {
		return errors.New("公钥不匹配")
	}
	kb.Lock()
	kb.pks[id] = key
	kb.Unlock()
	return nil
}

func (kb *keybook) PrivKey(p peer.ID) ic.PrivKey {
	kb.RLock()
	sk := kb.sks[p]
	kb.RUnlock()
	return sk
}

func (kb *keybook) AddPrivKey(p peer.ID, sk ic.PrivKey) error {

	if sk == nil {
		return errors.New("sk is nil (PrivKey)")
	}

	// check it's correct first
	if !p.MatchesPrivateKey(sk) {
		return errors.New("ID does not match PrivateKey")
	}

	kb.Lock()
	kb.sks[p] = sk
	kb.Unlock()
	return nil
}
