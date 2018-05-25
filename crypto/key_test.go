package crypto_test

import (
	"bytes"
	r "crypto/rand"
	m "math/rand"
	c "p2p/crypto"
	"testing"
	"time"
)

func randTestKeyPair(typ, bits int) (c.PrivKey, c.PubKey, error) {
	return sendTestKeyPair(typ, bits, time.Now().UnixNano())
}

func sendTestKeyPair(typ, bits int, send int64) (c.PrivKey, c.PubKey, error) {
	rand := m.New(m.NewSource(send))
	return c.GenerateKeyPairWithReader(typ, bits, rand)
}

func TestKeys(t *testing.T) {
	for _, typ := range c.KeyTypes {
		testKeyType(typ, t)
	}
}

func testKeyType(typ int, t *testing.T) {
	sk, pk, err := randTestKeyPair(typ, 512)
	if err != nil {
		t.Fatal(err)
	}

	testKeySignature(t, sk)
	testKeyEncoding(t, sk)
	testKeyEquals(t, sk)
	testKeyEquals(t, pk)
}

func testKeySignature(t *testing.T, sk c.PrivKey) {
	pk := sk.GetPublic()

	text := make([]byte, 16)
	r.Read(text)

	sig, err := sk.Sign(text)
	if err != nil {
		t.Fatal(err)
	}

	valid, err := pk.Verify(text, sig)
	if err != nil {
		t.Fatal(err)
	}

	if !valid {
		t.Fatal("Invalid signature.")
	}
}

func testKeyEncoding(t *testing.T, sk c.PrivKey) {
	skbm, err := c.MarshalPrivateKey(sk)
	if err != nil {
		t.Fatal(err)
	}

	sk2, err := c.UnmarshalPrivateKey(skbm)
	if err != nil {
		t.Fatal(err)
	}

	if !sk.Equals(sk2) {
		t.Error("Unmarshaled private key didn't match original.\n")
	}

	skbm2, err := c.MarshalPrivateKey(sk2)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(skbm, skbm2) {
		t.Error("skb -> marshal -> unmarshal -> skb failed.\n", skbm, "\n", skbm2)
	}

	pk := sk.GetPublic()
	pkbm, err := c.MarshalPublicKey(pk)
	if err != nil {
		t.Fatal(err)
	}

	pk2, err := c.UnmarshalPublicKey(pkbm)
	if err != nil {
		t.Fatal(err)
	}

	if !pk.Equals(pk2) {
		t.Error("Unmarshaled public key didn't match original.\n")
	}

	pkbm2, err := c.MarshalPublicKey(pk)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(pkbm, pkbm2) {
		t.Error("skb -> marshal -> unmarshal -> skb failed.\n", pkbm, "\n", pkbm2)
	}
}

func testKeyEquals(t *testing.T, k c.Key) {
	kb, err := k.Bytes()
	if err != nil {
		t.Fatal(err)
	}

	if !c.KeyEqual(k, k) {
		t.Fatal("Key not equal to itself.")
	}

	if !c.KeyEqual(k, testkey(kb)) {
		t.Fatal("Key not equal to key with same bytes.")
	}

	sk, pk, err := randTestKeyPair(c.RSA, 512)
	if err != nil {
		t.Fatal(err)
	}

	if c.KeyEqual(k, sk) {
		t.Fatal("Keys should not equal.")
	}

	if c.KeyEqual(k, pk) {
		t.Fatal("Keys should not equal.")
	}
}

type testkey []byte

func (pk testkey) Bytes() ([]byte, error) {
	return pk, nil
}

func (pk testkey) Equals(k c.Key) bool {
	return c.KeyEqual(pk, k)
}
