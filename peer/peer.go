package peer

import (
	"encoding/hex"
	"fmt"
	b58 "github.com/mr-tron/base58/base58"
	mh "github.com/multiformats/go-multihash"
	ic "p2p/crypto"
	"strings"
)

const MaxInlineKeyLength = 42

// ID is a peer identify
type ID string

func (id ID) Pretty() string {
	return IDB58Encode(id)
}

func IDB58Encode(id ID) string {
	return b58.Encode([]byte(id))
}

func (id ID) String() string {
	pid := id.Pretty()
	// sha256都是以Qm开头?
	if strings.HasPrefix(pid, "Qm") {
		pid = pid[2:]
	}
	maxRune := 6
	if len(pid) <= maxRune {
		maxRune = len(pid)
	}
	return fmt.Sprintf("<peer.ID %s>", pid[:maxRune])
}

func (id ID) MatchesPublicKey(pk ic.PubKey) bool {
	oid, err := IDFromPublicKey(pk)
	if err != nil {
		return false
	}
	return oid == id
}

func (id ID) MatchesPrivateKey(sk ic.PrivKey) bool {
	return id.MatchesPublicKey(sk.GetPublic())
}

// 提取public key
func (id ID) ExtractPublicKey() (ic.PubKey, error) {
	decoded, err := mh.Decode([]byte(id))
	if err != nil {
		return nil, err
	}
	if decoded.Code != mh.ID {
		return nil, err
	}
	pk, err := ic.UnmarshalPublicKey(decoded.Digest)
	if err != nil {
		return nil, err
	}
	return pk, err
}

func (id ID) IDFromString(s string) (ID, error) {
	if _, err := mh.Cast([]byte(s)); err != nil {
		return ID(""), err
	}
	return ID(s), nil
}

func (id ID) IDFromBytes(b []byte) (ID, error) {
	if _, err := mh.Cast(b); err != nil {
		return ID(""), err
	}
	return ID(b), nil
}

// IDB58Decode returns a b58-decoded Peer
func IDB58Decode(s string) (ID, error) {
	m, err := mh.FromB58String(s)
	if err != nil {
		return "", err
	}
	return ID(m), err
}

func IDHexEncode(id ID) string {
	return hex.EncodeToString([]byte(id))
}

// IDHexDecode returns a hex-decoded Peer
func IDHexDecode(s string) (ID, error) {
	m, err := mh.FromHexString(s)
	if err != nil {
		return "", err
	}
	return ID(m), err
}

func IDFromPublicKey(pk ic.PubKey) (ID, error) {
	b, err := pk.Bytes()
	if err != nil {
		return "", err
	}
	var alg uint64 = mh.SHA2_256
	if len(b) <= MaxInlineKeyLength {
		alg = mh.ID
	}
	hash, _ := mh.Sum(b, alg, -1)
	return ID(hash), nil
}

func IDFromPrivateKey(sk ic.PrivKey) (ID, error) {
	return IDFromPublicKey(sk.GetPublic())
}

// 根据ID进行排序
type IDSlice []ID

func (es IDSlice) Len() int           { return len(es) }
func (es IDSlice) Swap(i, j int)      { es[i], es[j] = es[j], es[i] }
func (es IDSlice) Less(i, j int) bool { return string(es[i]) < string(es[j]) }
