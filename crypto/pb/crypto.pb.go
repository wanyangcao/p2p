// Code generated by protoc-gen-go. DO NOT EDIT.
// source: crypto.proto

/*
Package crypto_pb is a generated protocol buffer package.

It is generated from these files:
	crypto.proto

It has these top-level messages:
	PublicKey
	PrivateKey
*/
package crypto_pb

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

type KeyType int32

const (
	KeyType_RSA       KeyType = 0
	KeyType_Ed25519   KeyType = 1
	KeyType_Secp256k1 KeyType = 2
)

var KeyType_name = map[int32]string{
	0: "RSA",
	1: "Ed25519",
	2: "Secp256k1",
}
var KeyType_value = map[string]int32{
	"RSA":       0,
	"Ed25519":   1,
	"Secp256k1": 2,
}

func (x KeyType) String() string {
	return proto.EnumName(KeyType_name, int32(x))
}
func (KeyType) EnumDescriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

type PublicKey struct {
	Type KeyType `protobuf:"varint,1,opt,name=Type,enum=crypto.pb.KeyType" json:"Type,omitempty"`
	Data []byte  `protobuf:"bytes,2,opt,name=Data,proto3" json:"Data,omitempty"`
}

func (m *PublicKey) Reset()                    { *m = PublicKey{} }
func (m *PublicKey) String() string            { return proto.CompactTextString(m) }
func (*PublicKey) ProtoMessage()               {}
func (*PublicKey) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

func (m *PublicKey) GetType() KeyType {
	if m != nil {
		return m.Type
	}
	return KeyType_RSA
}

func (m *PublicKey) GetData() []byte {
	if m != nil {
		return m.Data
	}
	return nil
}

type PrivateKey struct {
	Type KeyType `protobuf:"varint,1,opt,name=Type,enum=crypto.pb.KeyType" json:"Type,omitempty"`
	Data []byte  `protobuf:"bytes,2,opt,name=Data,proto3" json:"Data,omitempty"`
}

func (m *PrivateKey) Reset()                    { *m = PrivateKey{} }
func (m *PrivateKey) String() string            { return proto.CompactTextString(m) }
func (*PrivateKey) ProtoMessage()               {}
func (*PrivateKey) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{1} }

func (m *PrivateKey) GetType() KeyType {
	if m != nil {
		return m.Type
	}
	return KeyType_RSA
}

func (m *PrivateKey) GetData() []byte {
	if m != nil {
		return m.Data
	}
	return nil
}

func init() {
	proto.RegisterType((*PublicKey)(nil), "crypto.pb.PublicKey")
	proto.RegisterType((*PrivateKey)(nil), "crypto.pb.PrivateKey")
	proto.RegisterEnum("crypto.pb.KeyType", KeyType_name, KeyType_value)
}

func init() { proto.RegisterFile("crypto.proto", fileDescriptor0) }

var fileDescriptor0 = []byte{
	// 162 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0xe2, 0x49, 0x2e, 0xaa, 0x2c,
	0x28, 0xc9, 0xd7, 0x2b, 0x28, 0xca, 0x2f, 0xc9, 0x17, 0xe2, 0x84, 0xf1, 0x92, 0x94, 0xdc, 0xb9,
	0x38, 0x03, 0x4a, 0x93, 0x72, 0x32, 0x93, 0xbd, 0x53, 0x2b, 0x85, 0xd4, 0xb8, 0x58, 0x42, 0x2a,
	0x0b, 0x52, 0x25, 0x18, 0x15, 0x18, 0x35, 0xf8, 0x8c, 0x84, 0xf4, 0xe0, 0xca, 0xf4, 0xbc, 0x53,
	0x2b, 0x41, 0x32, 0x41, 0x60, 0x79, 0x21, 0x21, 0x2e, 0x16, 0x97, 0xc4, 0x92, 0x44, 0x09, 0x26,
	0x05, 0x46, 0x0d, 0x9e, 0x20, 0x30, 0x5b, 0xc9, 0x83, 0x8b, 0x2b, 0xa0, 0x28, 0xb3, 0x2c, 0xb1,
	0x24, 0x95, 0x42, 0x93, 0xb4, 0xf4, 0xb8, 0xd8, 0xa1, 0x8a, 0x84, 0xd8, 0xb9, 0x98, 0x83, 0x82,
	0x1d, 0x05, 0x18, 0x84, 0xb8, 0xb9, 0xd8, 0x5d, 0x53, 0x8c, 0x4c, 0x4d, 0x0d, 0x2d, 0x05, 0x18,
	0x85, 0x78, 0xb9, 0x38, 0x83, 0x53, 0x93, 0x0b, 0x8c, 0x4c, 0xcd, 0xb2, 0x0d, 0x05, 0x98, 0x92,
	0xd8, 0xc0, 0x9e, 0x32, 0x06, 0x04, 0x00, 0x00, 0xff, 0xff, 0x9b, 0x8e, 0x49, 0x36, 0xe4, 0x00,
	0x00, 0x00,
}
