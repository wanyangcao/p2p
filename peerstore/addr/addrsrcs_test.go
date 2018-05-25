package addr

import (
	"fmt"
	ma "github.com/multiformats/go-multiaddr"
	"testing"
)

func newAddrs(t *testing.T, n int) []ma.Multiaddr {
	addrs := make([]ma.Multiaddr, n)
	for i := 0; i < n; i++ {
		s := fmt.Sprintf("/ip4/1.2.3.4/tcp/%d", i)
		a, err := ma.NewMultiaddr(s)
		if err != nil {
			t.Fatal("解析地址失败", err)
		}
		addrs[i] = a
	}
	return addrs
}

func addrIsSame(a, b []ma.Multiaddr) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		bb := b[k]
		if !v.Equal(bb) {
			return false
		}
	}
	return true
}

func TestCombineSources(t *testing.T) {
	addrs := newAddrs(t, 30)
	a := Slice(addrs[0:10])
	b := Slice(addrs[10:20])
	c := Slice(addrs[20:30])
	d := CombineSources(a, b, c)
	if !addrIsSame(addrs, d.Addrs()) {
		t.Error("不相同")
	}
}
