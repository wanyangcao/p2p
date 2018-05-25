package addr

import (
	ma "github.com/multiformats/go-multiaddr"
)

type Source interface {
	Addrs() []ma.Multiaddr
}

type combineAS []Source

func (cas combineAS) Addrs() []ma.Multiaddr {
	var addrs []ma.Multiaddr
	for _, v := range cas {
		addrs = append(addrs, v.Addrs()...)
	}
	return addrs
}

func CombineSources(srcs ...Source) Source {
	return combineAS(srcs)
}

type uniqueAs []Source

func (uas uniqueAs) Addrs() []ma.Multiaddr {
	u := make(map[string]struct{})
	var addrs []ma.Multiaddr
	for _, s := range uas {
		for _, a := range s.Addrs() {
			ss := a.String()
			if _, found := u[ss]; !found {
				addrs = append(addrs, a)
				u[ss] = struct{}{}
			}
		}
	}
	return addrs
}

func UniqueSource(srcs ...Source) Source {
	return uniqueAs(srcs)
}

type Slice []ma.Multiaddr

func (as Slice) Addrs() []ma.Multiaddr {
	return as
}
