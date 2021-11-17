// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.27.1
// 	protoc        v3.18.0
// source: refs/grpc/types.proto

package refs

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// Checksum algorithm type.
type ChecksumType int32

const (
	// Unknown. Not used
	ChecksumType_CHECKSUM_TYPE_UNSPECIFIED ChecksumType = 0
	// Tillich-Zemor homomorphic hash function
	ChecksumType_TZ ChecksumType = 1
	// SHA-256
	ChecksumType_SHA256 ChecksumType = 2
)

// Enum value maps for ChecksumType.
var (
	ChecksumType_name = map[int32]string{
		0: "CHECKSUM_TYPE_UNSPECIFIED",
		1: "TZ",
		2: "SHA256",
	}
	ChecksumType_value = map[string]int32{
		"CHECKSUM_TYPE_UNSPECIFIED": 0,
		"TZ":                        1,
		"SHA256":                    2,
	}
)

func (x ChecksumType) Enum() *ChecksumType {
	p := new(ChecksumType)
	*p = x
	return p
}

func (x ChecksumType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (ChecksumType) Descriptor() protoreflect.EnumDescriptor {
	return file_refs_grpc_types_proto_enumTypes[0].Descriptor()
}

func (ChecksumType) Type() protoreflect.EnumType {
	return &file_refs_grpc_types_proto_enumTypes[0]
}

func (x ChecksumType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use ChecksumType.Descriptor instead.
func (ChecksumType) EnumDescriptor() ([]byte, []int) {
	return file_refs_grpc_types_proto_rawDescGZIP(), []int{0}
}

// Objects in NeoFS are addressed by their ContainerID and ObjectID.
//
// String presentation of `Address` is the concatenation of string encoded
// `ContainerID` and `ObjectID` delimited by '/' character.
type Address struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Container identifier
	ContainerId *ContainerID `protobuf:"bytes,1,opt,name=container_id,json=containerID,proto3" json:"container_id,omitempty"`
	// Object identifier
	ObjectId *ObjectID `protobuf:"bytes,2,opt,name=object_id,json=objectID,proto3" json:"object_id,omitempty"`
}

func (x *Address) Reset() {
	*x = Address{}
	if protoimpl.UnsafeEnabled {
		mi := &file_refs_grpc_types_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Address) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Address) ProtoMessage() {}

func (x *Address) ProtoReflect() protoreflect.Message {
	mi := &file_refs_grpc_types_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Address.ProtoReflect.Descriptor instead.
func (*Address) Descriptor() ([]byte, []int) {
	return file_refs_grpc_types_proto_rawDescGZIP(), []int{0}
}

func (x *Address) GetContainerId() *ContainerID {
	if x != nil {
		return x.ContainerId
	}
	return nil
}

func (x *Address) GetObjectId() *ObjectID {
	if x != nil {
		return x.ObjectId
	}
	return nil
}

// NeoFS Object unique identifier. Objects are immutable and content-addressed.
// It means `ObjectID` will change if `header` or `payload` changes.
//
// `ObjectID` is a 32 byte long
// [SHA256](https://csrc.nist.gov/publications/detail/fips/180/4/final) hash of
// object's `header` field, which, in it's turn, contains hash of object's
// payload.
//
// String presentation is
// [base58](https://tools.ietf.org/html/draft-msporny-base58-02) encoded string.
//
// JSON value will be the data encoded as a string using standard base64
// encoding with paddings. Either
// [standard](https://tools.ietf.org/html/rfc4648#section-4) or
// [URL-safe](https://tools.ietf.org/html/rfc4648#section-5) base64 encoding
// with/without paddings are accepted.
type ObjectID struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Object identifier in a binary format
	Value []byte `protobuf:"bytes,1,opt,name=value,proto3" json:"value,omitempty"`
}

func (x *ObjectID) Reset() {
	*x = ObjectID{}
	if protoimpl.UnsafeEnabled {
		mi := &file_refs_grpc_types_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ObjectID) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ObjectID) ProtoMessage() {}

func (x *ObjectID) ProtoReflect() protoreflect.Message {
	mi := &file_refs_grpc_types_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ObjectID.ProtoReflect.Descriptor instead.
func (*ObjectID) Descriptor() ([]byte, []int) {
	return file_refs_grpc_types_proto_rawDescGZIP(), []int{1}
}

func (x *ObjectID) GetValue() []byte {
	if x != nil {
		return x.Value
	}
	return nil
}

// NeoFS container identifier. Container structures are immutable and
// content-addressed.
//
// `ContainerID` is a 32 byte long
// [SHA256](https://csrc.nist.gov/publications/detail/fips/180/4/final) hash of
// stable-marshalled container message.
//
// String presentation is
// [base58](https://tools.ietf.org/html/draft-msporny-base58-02) encoded string.
//
// JSON value will be the data encoded as a string using standard base64
// encoding with paddings. Either
// [standard](https://tools.ietf.org/html/rfc4648#section-4) or
// [URL-safe](https://tools.ietf.org/html/rfc4648#section-5) base64 encoding
// with/without paddings are accepted.
type ContainerID struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Container identifier in a binary format.
	Value []byte `protobuf:"bytes,1,opt,name=value,proto3" json:"value,omitempty"`
}

func (x *ContainerID) Reset() {
	*x = ContainerID{}
	if protoimpl.UnsafeEnabled {
		mi := &file_refs_grpc_types_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ContainerID) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ContainerID) ProtoMessage() {}

func (x *ContainerID) ProtoReflect() protoreflect.Message {
	mi := &file_refs_grpc_types_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ContainerID.ProtoReflect.Descriptor instead.
func (*ContainerID) Descriptor() ([]byte, []int) {
	return file_refs_grpc_types_proto_rawDescGZIP(), []int{2}
}

func (x *ContainerID) GetValue() []byte {
	if x != nil {
		return x.Value
	}
	return nil
}

// `OwnerID` is a derivative of a user's main public key. The transformation
// algorithm is the same as for Neo3 wallet addresses. Neo3 wallet address can
// be directly used as `OwnerID`.
//
// `OwnerID` is a 25 bytes sequence starting with Neo version prefix byte
// followed by 20 bytes of ScrptHash and 4 bytes of checksum.
//
// String presentation is [Base58
// Check](https://en.bitcoin.it/wiki/Base58Check_encoding) Encoded string.
//
// JSON value will be the data encoded as a string using standard base64
// encoding with paddings. Either
// [standard](https://tools.ietf.org/html/rfc4648#section-4) or
// [URL-safe](https://tools.ietf.org/html/rfc4648#section-5) base64 encoding
// with/without paddings are accepted.
type OwnerID struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Identifier of the container owner in a binary format
	Value []byte `protobuf:"bytes,1,opt,name=value,proto3" json:"value,omitempty"`
}

func (x *OwnerID) Reset() {
	*x = OwnerID{}
	if protoimpl.UnsafeEnabled {
		mi := &file_refs_grpc_types_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *OwnerID) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*OwnerID) ProtoMessage() {}

func (x *OwnerID) ProtoReflect() protoreflect.Message {
	mi := &file_refs_grpc_types_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use OwnerID.ProtoReflect.Descriptor instead.
func (*OwnerID) Descriptor() ([]byte, []int) {
	return file_refs_grpc_types_proto_rawDescGZIP(), []int{3}
}

func (x *OwnerID) GetValue() []byte {
	if x != nil {
		return x.Value
	}
	return nil
}

// NeoFS subnetwork identifier.
//
// String representation of a value is base-10 integer.
//
// JSON representation is an object containing single `value` number field.
type SubnetID struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// 4-byte integer subnetwork identifier.
	Value uint32 `protobuf:"fixed32,1,opt,name=value,proto3" json:"value,omitempty"`
}

func (x *SubnetID) Reset() {
	*x = SubnetID{}
	if protoimpl.UnsafeEnabled {
		mi := &file_refs_grpc_types_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SubnetID) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SubnetID) ProtoMessage() {}

func (x *SubnetID) ProtoReflect() protoreflect.Message {
	mi := &file_refs_grpc_types_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SubnetID.ProtoReflect.Descriptor instead.
func (*SubnetID) Descriptor() ([]byte, []int) {
	return file_refs_grpc_types_proto_rawDescGZIP(), []int{4}
}

func (x *SubnetID) GetValue() uint32 {
	if x != nil {
		return x.Value
	}
	return 0
}

// API version used by a node.
//
// String presentation is a Semantic Versioning 2.0.0 compatible version string
// with 'v' prefix. I.e. `vX.Y`, where `X` - major number, `Y` - minor number.
type Version struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Major API version
	Major uint32 `protobuf:"varint,1,opt,name=major,proto3" json:"major,omitempty"`
	// Minor API version
	Minor uint32 `protobuf:"varint,2,opt,name=minor,proto3" json:"minor,omitempty"`
}

func (x *Version) Reset() {
	*x = Version{}
	if protoimpl.UnsafeEnabled {
		mi := &file_refs_grpc_types_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Version) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Version) ProtoMessage() {}

func (x *Version) ProtoReflect() protoreflect.Message {
	mi := &file_refs_grpc_types_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Version.ProtoReflect.Descriptor instead.
func (*Version) Descriptor() ([]byte, []int) {
	return file_refs_grpc_types_proto_rawDescGZIP(), []int{5}
}

func (x *Version) GetMajor() uint32 {
	if x != nil {
		return x.Major
	}
	return 0
}

func (x *Version) GetMinor() uint32 {
	if x != nil {
		return x.Minor
	}
	return 0
}

// Signature of something in NeoFS.
type Signature struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Public key used for signing
	Key []byte `protobuf:"bytes,1,opt,name=key,proto3" json:"key,omitempty"`
	// Signature
	Sign []byte `protobuf:"bytes,2,opt,name=sign,json=signature,proto3" json:"sign,omitempty"`
}

func (x *Signature) Reset() {
	*x = Signature{}
	if protoimpl.UnsafeEnabled {
		mi := &file_refs_grpc_types_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Signature) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Signature) ProtoMessage() {}

func (x *Signature) ProtoReflect() protoreflect.Message {
	mi := &file_refs_grpc_types_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Signature.ProtoReflect.Descriptor instead.
func (*Signature) Descriptor() ([]byte, []int) {
	return file_refs_grpc_types_proto_rawDescGZIP(), []int{6}
}

func (x *Signature) GetKey() []byte {
	if x != nil {
		return x.Key
	}
	return nil
}

func (x *Signature) GetSign() []byte {
	if x != nil {
		return x.Sign
	}
	return nil
}

// Checksum message.
// Depending on checksum algorithm type the string presentation may vary:
//
// * TZ \
//   Hex encoded string without `0x` prefix
// * SHA256 \
//   Hex encoded string without `0x` prefix
type Checksum struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Checksum algorithm type
	Type ChecksumType `protobuf:"varint,1,opt,name=type,proto3,enum=neo.fs.v2.refs.ChecksumType" json:"type,omitempty"`
	// Checksum itself
	Sum []byte `protobuf:"bytes,2,opt,name=sum,proto3" json:"sum,omitempty"`
}

func (x *Checksum) Reset() {
	*x = Checksum{}
	if protoimpl.UnsafeEnabled {
		mi := &file_refs_grpc_types_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Checksum) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Checksum) ProtoMessage() {}

func (x *Checksum) ProtoReflect() protoreflect.Message {
	mi := &file_refs_grpc_types_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Checksum.ProtoReflect.Descriptor instead.
func (*Checksum) Descriptor() ([]byte, []int) {
	return file_refs_grpc_types_proto_rawDescGZIP(), []int{7}
}

func (x *Checksum) GetType() ChecksumType {
	if x != nil {
		return x.Type
	}
	return ChecksumType_CHECKSUM_TYPE_UNSPECIFIED
}

func (x *Checksum) GetSum() []byte {
	if x != nil {
		return x.Sum
	}
	return nil
}

var File_refs_grpc_types_proto protoreflect.FileDescriptor

var file_refs_grpc_types_proto_rawDesc = []byte{
	0x0a, 0x15, 0x72, 0x65, 0x66, 0x73, 0x2f, 0x67, 0x72, 0x70, 0x63, 0x2f, 0x74, 0x79, 0x70, 0x65,
	0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0e, 0x6e, 0x65, 0x6f, 0x2e, 0x66, 0x73, 0x2e,
	0x76, 0x32, 0x2e, 0x72, 0x65, 0x66, 0x73, 0x22, 0x80, 0x01, 0x0a, 0x07, 0x41, 0x64, 0x64, 0x72,
	0x65, 0x73, 0x73, 0x12, 0x3e, 0x0a, 0x0c, 0x63, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72,
	0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1b, 0x2e, 0x6e, 0x65, 0x6f, 0x2e,
	0x66, 0x73, 0x2e, 0x76, 0x32, 0x2e, 0x72, 0x65, 0x66, 0x73, 0x2e, 0x43, 0x6f, 0x6e, 0x74, 0x61,
	0x69, 0x6e, 0x65, 0x72, 0x49, 0x44, 0x52, 0x0b, 0x63, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65,
	0x72, 0x49, 0x44, 0x12, 0x35, 0x0a, 0x09, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x5f, 0x69, 0x64,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x18, 0x2e, 0x6e, 0x65, 0x6f, 0x2e, 0x66, 0x73, 0x2e,
	0x76, 0x32, 0x2e, 0x72, 0x65, 0x66, 0x73, 0x2e, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x49, 0x44,
	0x52, 0x08, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x49, 0x44, 0x22, 0x20, 0x0a, 0x08, 0x4f, 0x62,
	0x6a, 0x65, 0x63, 0x74, 0x49, 0x44, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x22, 0x23, 0x0a, 0x0b,
	0x43, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x49, 0x44, 0x12, 0x14, 0x0a, 0x05, 0x76,
	0x61, 0x6c, 0x75, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75,
	0x65, 0x22, 0x1f, 0x0a, 0x07, 0x4f, 0x77, 0x6e, 0x65, 0x72, 0x49, 0x44, 0x12, 0x14, 0x0a, 0x05,
	0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x05, 0x76, 0x61, 0x6c,
	0x75, 0x65, 0x22, 0x20, 0x0a, 0x08, 0x53, 0x75, 0x62, 0x6e, 0x65, 0x74, 0x49, 0x44, 0x12, 0x14,
	0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x07, 0x52, 0x05, 0x76,
	0x61, 0x6c, 0x75, 0x65, 0x22, 0x35, 0x0a, 0x07, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x12,
	0x14, 0x0a, 0x05, 0x6d, 0x61, 0x6a, 0x6f, 0x72, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x05,
	0x6d, 0x61, 0x6a, 0x6f, 0x72, 0x12, 0x14, 0x0a, 0x05, 0x6d, 0x69, 0x6e, 0x6f, 0x72, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x0d, 0x52, 0x05, 0x6d, 0x69, 0x6e, 0x6f, 0x72, 0x22, 0x36, 0x0a, 0x09, 0x53,
	0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x17, 0x0a, 0x04, 0x73, 0x69,
	0x67, 0x6e, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x09, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74,
	0x75, 0x72, 0x65, 0x22, 0x4e, 0x0a, 0x08, 0x43, 0x68, 0x65, 0x63, 0x6b, 0x73, 0x75, 0x6d, 0x12,
	0x30, 0x0a, 0x04, 0x74, 0x79, 0x70, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x1c, 0x2e,
	0x6e, 0x65, 0x6f, 0x2e, 0x66, 0x73, 0x2e, 0x76, 0x32, 0x2e, 0x72, 0x65, 0x66, 0x73, 0x2e, 0x43,
	0x68, 0x65, 0x63, 0x6b, 0x73, 0x75, 0x6d, 0x54, 0x79, 0x70, 0x65, 0x52, 0x04, 0x74, 0x79, 0x70,
	0x65, 0x12, 0x10, 0x0a, 0x03, 0x73, 0x75, 0x6d, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x03,
	0x73, 0x75, 0x6d, 0x2a, 0x41, 0x0a, 0x0c, 0x43, 0x68, 0x65, 0x63, 0x6b, 0x73, 0x75, 0x6d, 0x54,
	0x79, 0x70, 0x65, 0x12, 0x1d, 0x0a, 0x19, 0x43, 0x48, 0x45, 0x43, 0x4b, 0x53, 0x55, 0x4d, 0x5f,
	0x54, 0x59, 0x50, 0x45, 0x5f, 0x55, 0x4e, 0x53, 0x50, 0x45, 0x43, 0x49, 0x46, 0x49, 0x45, 0x44,
	0x10, 0x00, 0x12, 0x06, 0x0a, 0x02, 0x54, 0x5a, 0x10, 0x01, 0x12, 0x0a, 0x0a, 0x06, 0x53, 0x48,
	0x41, 0x32, 0x35, 0x36, 0x10, 0x02, 0x42, 0x50, 0x5a, 0x33, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62,
	0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x6e, 0x73, 0x70, 0x63, 0x63, 0x2d, 0x64, 0x65, 0x76, 0x2f, 0x6e,
	0x65, 0x6f, 0x66, 0x73, 0x2d, 0x61, 0x70, 0x69, 0x2d, 0x67, 0x6f, 0x2f, 0x76, 0x32, 0x2f, 0x72,
	0x65, 0x66, 0x73, 0x2f, 0x67, 0x72, 0x70, 0x63, 0x3b, 0x72, 0x65, 0x66, 0x73, 0xaa, 0x02, 0x18,
	0x4e, 0x65, 0x6f, 0x2e, 0x46, 0x69, 0x6c, 0x65, 0x53, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x2e,
	0x41, 0x50, 0x49, 0x2e, 0x52, 0x65, 0x66, 0x73, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_refs_grpc_types_proto_rawDescOnce sync.Once
	file_refs_grpc_types_proto_rawDescData = file_refs_grpc_types_proto_rawDesc
)

func file_refs_grpc_types_proto_rawDescGZIP() []byte {
	file_refs_grpc_types_proto_rawDescOnce.Do(func() {
		file_refs_grpc_types_proto_rawDescData = protoimpl.X.CompressGZIP(file_refs_grpc_types_proto_rawDescData)
	})
	return file_refs_grpc_types_proto_rawDescData
}

var file_refs_grpc_types_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_refs_grpc_types_proto_msgTypes = make([]protoimpl.MessageInfo, 8)
var file_refs_grpc_types_proto_goTypes = []interface{}{
	(ChecksumType)(0),   // 0: neo.fs.v2.refs.ChecksumType
	(*Address)(nil),     // 1: neo.fs.v2.refs.Address
	(*ObjectID)(nil),    // 2: neo.fs.v2.refs.ObjectID
	(*ContainerID)(nil), // 3: neo.fs.v2.refs.ContainerID
	(*OwnerID)(nil),     // 4: neo.fs.v2.refs.OwnerID
	(*SubnetID)(nil),    // 5: neo.fs.v2.refs.SubnetID
	(*Version)(nil),     // 6: neo.fs.v2.refs.Version
	(*Signature)(nil),   // 7: neo.fs.v2.refs.Signature
	(*Checksum)(nil),    // 8: neo.fs.v2.refs.Checksum
}
var file_refs_grpc_types_proto_depIdxs = []int32{
	3, // 0: neo.fs.v2.refs.Address.container_id:type_name -> neo.fs.v2.refs.ContainerID
	2, // 1: neo.fs.v2.refs.Address.object_id:type_name -> neo.fs.v2.refs.ObjectID
	0, // 2: neo.fs.v2.refs.Checksum.type:type_name -> neo.fs.v2.refs.ChecksumType
	3, // [3:3] is the sub-list for method output_type
	3, // [3:3] is the sub-list for method input_type
	3, // [3:3] is the sub-list for extension type_name
	3, // [3:3] is the sub-list for extension extendee
	0, // [0:3] is the sub-list for field type_name
}

func init() { file_refs_grpc_types_proto_init() }
func file_refs_grpc_types_proto_init() {
	if File_refs_grpc_types_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_refs_grpc_types_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Address); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_refs_grpc_types_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ObjectID); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_refs_grpc_types_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ContainerID); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_refs_grpc_types_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*OwnerID); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_refs_grpc_types_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SubnetID); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_refs_grpc_types_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Version); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_refs_grpc_types_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Signature); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_refs_grpc_types_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Checksum); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_refs_grpc_types_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   8,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_refs_grpc_types_proto_goTypes,
		DependencyIndexes: file_refs_grpc_types_proto_depIdxs,
		EnumInfos:         file_refs_grpc_types_proto_enumTypes,
		MessageInfos:      file_refs_grpc_types_proto_msgTypes,
	}.Build()
	File_refs_grpc_types_proto = out.File
	file_refs_grpc_types_proto_rawDesc = nil
	file_refs_grpc_types_proto_goTypes = nil
	file_refs_grpc_types_proto_depIdxs = nil
}
