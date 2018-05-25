package peer

import (
	"encoding/base64"
	"fmt"
	b58 "github.com/mr-tron/base58/base58"
	mh "github.com/multiformats/go-multihash"
	"math/rand"
	ci "p2p/crypto"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

var skManBytes = `
CAAS4AQwggJcAgEAAoGBAL7w+Wc4VhZhCdM/+Hccg5Nrf4q9NXWwJylbSrXz/unFS24wyk6pEk0zi3W
7li+vSNVO+NtJQw9qGNAMtQKjVTP+3Vt/jfQRnQM3s6awojtjueEWuLYVt62z7mofOhCtj+VwIdZNBo
/EkLZ0ETfcvN5LVtLYa8JkXybnOPsLvK+PAgMBAAECgYBdk09HDM7zzL657uHfzfOVrdslrTCj6p5mo
DzvCxLkkjIzYGnlPuqfNyGjozkpSWgSUc+X+EGLLl3WqEOVdWJtbM61fewEHlRTM5JzScvwrJ39t7o6
CCAjKA0cBWBd6UWgbN/t53RoWvh9HrA2AW5YrT0ZiAgKe9y7EMUaENVJ8QJBAPhpdmb4ZL4Fkm4OKia
NEcjzn6mGTlZtef7K/0oRC9+2JkQnCuf6HBpaRhJoCJYg7DW8ZY+AV6xClKrgjBOfERMCQQDExhnzu2
dsQ9k8QChBlpHO0TRbZBiQfC70oU31kM1AeLseZRmrxv9Yxzdl8D693NNWS2JbKOXl0kMHHcuGQLMVA
kBZ7WvkmPV3aPL6jnwp2pXepntdVnaTiSxJ1dkXShZ/VSSDNZMYKY306EtHrIu3NZHtXhdyHKcggDXr
qkBrdgErAkAlpGPojUwemOggr4FD8sLX1ot2hDJyyV7OK2FXfajWEYJyMRL1Gm9Uk1+Un53RAkJneqp
JGAzKpyttXBTIDO51AkEA98KTiROMnnU8Y6Mgcvr68/SMIsvCYMt9/mtwSBGgl80VaTQ5Hpaktl6Xbh
VUt5Wv0tRxlXZiViCGCD1EtrrwTw==
`
var hpkpMan = `QmRK3JgmVEGiewxWbhpXLJyjWuGuLeSTMTndA1coMHEy5o`

type keySet struct {
	pk   ci.PubKey
	sk   ci.PrivKey
	hpk  string
	hpkp string
}

var gen1 keySet
var gen2 keySet
var man keySet

func (ks *keySet) generate() error {
	var err error
	ks.sk, ks.pk, err = randTestKeyPair(512)
	if err != nil {
		return err
	}
	bpk, err := ks.pk.Bytes()
	if err != nil {
		return err
	}

	ks.hpk = string(hash(bpk))
	ks.hpkp = b58.Encode([]byte(ks.hpk))
	return nil
}

func (ks *keySet) load(hpkp, skBytesStr string) error {
	skBytes, err := base64.StdEncoding.DecodeString(skBytesStr)
	if err != nil {
		return err
	}
	ks.sk, err = ci.UnmarshalPrivateKey(skBytes)
	if err != nil {
		return nil
	}
	ks.pk = ks.sk.GetPublic()
	bpk, err := ks.pk.Bytes()
	if err != nil {
		return err
	}

	ks.hpk = string(hash(bpk))
	ks.hpkp = b58.Encode([]byte(ks.hpk))
	if ks.hpkp != hpkp {
		return fmt.Errorf("hpkp doesn't match key. %s", hpkp)
	}
	return nil
}

func init() {
	if err := gen1.generate(); err != nil {
		panic(err)
	}
	if err := gen2.generate(); err != nil {
		panic(err)
	}

	skManBytes = strings.Replace(skManBytes, "\n", "", -1)
	if err := man.load(hpkpMan, skManBytes); err != nil {
		panic(err)
	}
}

func TestIDMatchesPublicKey(t *testing.T) {

	test := func(ks keySet) {
		p1, err := IDB58Decode(ks.hpkp)
		if err != nil {
			t.Fatal(err)
		}

		if ks.hpk != string(p1) {
			t.Error("p1 and hpk differ")
		}

		if !p1.MatchesPublicKey(ks.pk) {
			t.Fatal("p1 does not match pk")
		}

		p2, err := IDFromPublicKey(ks.pk)
		if err != nil {
			t.Fatal(err)
		}

		if p1 != p2 {
			t.Error("p1 and p2 differ", p1.Pretty(), p2.Pretty())
		}

		if p2.Pretty() != ks.hpkp {
			t.Error("hpkp and p2.Pretty differ", ks.hpkp, p2.Pretty())
		}
	}

	test(gen1)
	test(gen2)
	test(man)
}

var generatedPairs int64 = 0

func randTestKeyPair(bits int) (ci.PrivKey, ci.PubKey, error) {
	seed := time.Now().UnixNano()
	seed += atomic.AddInt64(&generatedPairs, 1) << 32
	r := rand.New(rand.NewSource(seed))
	return ci.GenerateKeyPairWithReader(ci.RSA, bits, r)
}

func hash(b []byte) []byte {
	h, _ := mh.Sum(b, mh.SHA2_256, -1)
	return []byte(h)
}
