// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: container/types.proto

package container

import (
	fmt "fmt"
	_ "github.com/gogo/protobuf/gogoproto"
	proto "github.com/golang/protobuf/proto"
	netmap "github.com/nspcc-dev/netmap"
	io "io"
	math "math"
	math_bits "math/bits"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

// The Container service definition.
type Container struct {
	// OwnerID is a wallet address.
	OwnerID OwnerID `protobuf:"bytes,1,opt,name=OwnerID,proto3,customtype=OwnerID" json:"OwnerID"`
	// Salt is a nonce for unique container id calculation.
	Salt UUID `protobuf:"bytes,2,opt,name=Salt,proto3,customtype=UUID" json:"Salt"`
	// Capacity defines amount of data that can be stored in the container (doesn't used for now).
	Capacity uint64 `protobuf:"varint,3,opt,name=Capacity,proto3" json:"Capacity,omitempty"`
	// Rules define storage policy for the object inside the container.
	Rules netmap.PlacementRule `protobuf:"bytes,4,opt,name=Rules,proto3" json:"Rules"`
	// Container ACL.
	List                 AccessControlList `protobuf:"bytes,5,opt,name=List,proto3" json:"List"`
	XXX_NoUnkeyedLiteral struct{}          `json:"-"`
	XXX_unrecognized     []byte            `json:"-"`
	XXX_sizecache        int32             `json:"-"`
}

func (m *Container) Reset()         { *m = Container{} }
func (m *Container) String() string { return proto.CompactTextString(m) }
func (*Container) ProtoMessage()    {}
func (*Container) Descriptor() ([]byte, []int) {
	return fileDescriptor_1432e52ab0b53e3e, []int{0}
}
func (m *Container) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *Container) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	b = b[:cap(b)]
	n, err := m.MarshalToSizedBuffer(b)
	if err != nil {
		return nil, err
	}
	return b[:n], nil
}
func (m *Container) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Container.Merge(m, src)
}
func (m *Container) XXX_Size() int {
	return m.Size()
}
func (m *Container) XXX_DiscardUnknown() {
	xxx_messageInfo_Container.DiscardUnknown(m)
}

var xxx_messageInfo_Container proto.InternalMessageInfo

func (m *Container) GetCapacity() uint64 {
	if m != nil {
		return m.Capacity
	}
	return 0
}

func (m *Container) GetRules() netmap.PlacementRule {
	if m != nil {
		return m.Rules
	}
	return netmap.PlacementRule{}
}

func (m *Container) GetList() AccessControlList {
	if m != nil {
		return m.List
	}
	return AccessControlList{}
}

type AccessGroup struct {
	// Group access mode.
	AccessMode uint32 `protobuf:"varint,1,opt,name=AccessMode,proto3" json:"AccessMode,omitempty"`
	// Group members.
	UserGroup            []OwnerID `protobuf:"bytes,2,rep,name=UserGroup,proto3,customtype=OwnerID" json:"UserGroup"`
	XXX_NoUnkeyedLiteral struct{}  `json:"-"`
	XXX_unrecognized     []byte    `json:"-"`
	XXX_sizecache        int32     `json:"-"`
}

func (m *AccessGroup) Reset()         { *m = AccessGroup{} }
func (m *AccessGroup) String() string { return proto.CompactTextString(m) }
func (*AccessGroup) ProtoMessage()    {}
func (*AccessGroup) Descriptor() ([]byte, []int) {
	return fileDescriptor_1432e52ab0b53e3e, []int{1}
}
func (m *AccessGroup) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *AccessGroup) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	b = b[:cap(b)]
	n, err := m.MarshalToSizedBuffer(b)
	if err != nil {
		return nil, err
	}
	return b[:n], nil
}
func (m *AccessGroup) XXX_Merge(src proto.Message) {
	xxx_messageInfo_AccessGroup.Merge(m, src)
}
func (m *AccessGroup) XXX_Size() int {
	return m.Size()
}
func (m *AccessGroup) XXX_DiscardUnknown() {
	xxx_messageInfo_AccessGroup.DiscardUnknown(m)
}

var xxx_messageInfo_AccessGroup proto.InternalMessageInfo

func (m *AccessGroup) GetAccessMode() uint32 {
	if m != nil {
		return m.AccessMode
	}
	return 0
}

type AccessControlList struct {
	// List of access groups.
	List                 []AccessGroup `protobuf:"bytes,1,rep,name=List,proto3" json:"List"`
	XXX_NoUnkeyedLiteral struct{}      `json:"-"`
	XXX_unrecognized     []byte        `json:"-"`
	XXX_sizecache        int32         `json:"-"`
}

func (m *AccessControlList) Reset()         { *m = AccessControlList{} }
func (m *AccessControlList) String() string { return proto.CompactTextString(m) }
func (*AccessControlList) ProtoMessage()    {}
func (*AccessControlList) Descriptor() ([]byte, []int) {
	return fileDescriptor_1432e52ab0b53e3e, []int{2}
}
func (m *AccessControlList) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *AccessControlList) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	b = b[:cap(b)]
	n, err := m.MarshalToSizedBuffer(b)
	if err != nil {
		return nil, err
	}
	return b[:n], nil
}
func (m *AccessControlList) XXX_Merge(src proto.Message) {
	xxx_messageInfo_AccessControlList.Merge(m, src)
}
func (m *AccessControlList) XXX_Size() int {
	return m.Size()
}
func (m *AccessControlList) XXX_DiscardUnknown() {
	xxx_messageInfo_AccessControlList.DiscardUnknown(m)
}

var xxx_messageInfo_AccessControlList proto.InternalMessageInfo

func (m *AccessControlList) GetList() []AccessGroup {
	if m != nil {
		return m.List
	}
	return nil
}

func init() {
	proto.RegisterType((*Container)(nil), "container.Container")
	proto.RegisterType((*AccessGroup)(nil), "container.AccessGroup")
	proto.RegisterType((*AccessControlList)(nil), "container.AccessControlList")
}

func init() { proto.RegisterFile("container/types.proto", fileDescriptor_1432e52ab0b53e3e) }

var fileDescriptor_1432e52ab0b53e3e = []byte{
	// 393 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x74, 0x91, 0x4d, 0x6b, 0xe2, 0x40,
	0x1c, 0xc6, 0x1d, 0x8d, 0xbb, 0xeb, 0xe8, 0xb2, 0xec, 0x2c, 0x2e, 0x41, 0x96, 0x18, 0x3c, 0x65,
	0x77, 0xc9, 0x64, 0xd7, 0x42, 0xef, 0xbe, 0xb4, 0x45, 0xe8, 0x8b, 0x44, 0xa4, 0x50, 0x7a, 0x89,
	0xe3, 0x98, 0x06, 0x62, 0x26, 0x64, 0x26, 0x2d, 0x7e, 0x93, 0x7e, 0x86, 0x7e, 0x12, 0x8f, 0x3d,
	0x96, 0x1e, 0x6c, 0x49, 0xbf, 0x48, 0xc9, 0x44, 0x53, 0xc1, 0xf6, 0x36, 0xcf, 0x33, 0xbf, 0x67,
	0xe6, 0xff, 0x02, 0xeb, 0x84, 0x05, 0xc2, 0xf1, 0x02, 0x1a, 0x59, 0x62, 0x11, 0x52, 0x8e, 0xc3,
	0x88, 0x09, 0x86, 0x2a, 0xb9, 0xdd, 0xf8, 0xe3, 0x7a, 0xe2, 0x2a, 0x9e, 0x60, 0xc2, 0xe6, 0x56,
	0xc0, 0x43, 0x42, 0xcc, 0x29, 0xbd, 0xb6, 0x02, 0x2a, 0xe6, 0x4e, 0x68, 0x71, 0xea, 0x53, 0x22,
	0x58, 0x94, 0xc5, 0x1a, 0xe6, 0x16, 0xeb, 0x32, 0x97, 0x59, 0xd2, 0x9e, 0xc4, 0x33, 0xa9, 0xa4,
	0x90, 0xa7, 0x0c, 0x6f, 0x3d, 0x01, 0x58, 0xe9, 0x6d, 0x3e, 0x42, 0xbf, 0xe1, 0xe7, 0xb3, 0x9b,
	0x80, 0x46, 0x83, 0xbe, 0x0a, 0x74, 0x60, 0xd4, 0xba, 0xdf, 0x96, 0xab, 0x66, 0xe1, 0x71, 0xd5,
	0xdc, 0xd8, 0xf6, 0xe6, 0x80, 0x74, 0xa8, 0x8c, 0x1c, 0x5f, 0xa8, 0x45, 0xc9, 0xd5, 0xd6, 0x9c,
	0x32, 0x1e, 0x0f, 0xfa, 0xb6, 0xbc, 0x41, 0x0d, 0xf8, 0xa5, 0xe7, 0x84, 0x0e, 0xf1, 0xc4, 0x42,
	0x2d, 0xe9, 0xc0, 0x50, 0xec, 0x5c, 0xa3, 0xff, 0xb0, 0x6c, 0xc7, 0x3e, 0xe5, 0xaa, 0xa2, 0x03,
	0xa3, 0xda, 0xae, 0xe3, 0xac, 0x19, 0x3c, 0xf4, 0x1d, 0x42, 0xe7, 0x34, 0x10, 0xe9, 0x6d, 0x57,
	0x49, 0x5f, 0xb5, 0x33, 0x12, 0xed, 0x43, 0xe5, 0xd8, 0xe3, 0x42, 0x2d, 0xcb, 0xc4, 0x2f, 0x9c,
	0x8f, 0x07, 0x77, 0x08, 0xa1, 0x9c, 0xa7, 0x5d, 0x44, 0xcc, 0x4f, 0x99, 0x75, 0x50, 0xf2, 0xad,
	0x4b, 0x58, 0xcd, 0x80, 0xa3, 0x88, 0xc5, 0x21, 0xd2, 0x20, 0xcc, 0xe4, 0x09, 0x9b, 0x52, 0xd9,
	0xe5, 0x57, 0x7b, 0xcb, 0x41, 0x26, 0xac, 0x8c, 0x39, 0x8d, 0x24, 0xac, 0x16, 0xf5, 0xd2, 0x7b,
	0x43, 0x78, 0x23, 0x5a, 0x07, 0xf0, 0xfb, 0xce, 0xf7, 0xe8, 0xdf, 0xba, 0x54, 0xa0, 0x97, 0x8c,
	0x6a, 0xfb, 0xe7, 0x4e, 0xa9, 0x32, 0xba, 0x5d, 0x64, 0xf7, 0x7c, 0x99, 0x68, 0xe0, 0x3e, 0xd1,
	0xc0, 0x43, 0xa2, 0x81, 0xe7, 0x44, 0x03, 0xb7, 0x2f, 0x5a, 0xe1, 0xe2, 0xef, 0x07, 0x7b, 0x67,
	0x33, 0x6e, 0x3a, 0xa1, 0x67, 0xba, 0xcc, 0xca, 0x9f, 0xbe, 0x2b, 0xfe, 0x38, 0xa5, 0xec, 0x70,
	0x84, 0x3b, 0xc3, 0x01, 0xce, 0x37, 0x3a, 0xf9, 0x24, 0xd7, 0xbc, 0xf7, 0x1a, 0x00, 0x00, 0xff,
	0xff, 0xd2, 0x94, 0x7a, 0x2b, 0x65, 0x02, 0x00, 0x00,
}

func (m *Container) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *Container) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *Container) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.XXX_unrecognized != nil {
		i -= len(m.XXX_unrecognized)
		copy(dAtA[i:], m.XXX_unrecognized)
	}
	{
		size, err := m.List.MarshalToSizedBuffer(dAtA[:i])
		if err != nil {
			return 0, err
		}
		i -= size
		i = encodeVarintTypes(dAtA, i, uint64(size))
	}
	i--
	dAtA[i] = 0x2a
	{
		size, err := m.Rules.MarshalToSizedBuffer(dAtA[:i])
		if err != nil {
			return 0, err
		}
		i -= size
		i = encodeVarintTypes(dAtA, i, uint64(size))
	}
	i--
	dAtA[i] = 0x22
	if m.Capacity != 0 {
		i = encodeVarintTypes(dAtA, i, uint64(m.Capacity))
		i--
		dAtA[i] = 0x18
	}
	{
		size := m.Salt.Size()
		i -= size
		if _, err := m.Salt.MarshalTo(dAtA[i:]); err != nil {
			return 0, err
		}
		i = encodeVarintTypes(dAtA, i, uint64(size))
	}
	i--
	dAtA[i] = 0x12
	{
		size := m.OwnerID.Size()
		i -= size
		if _, err := m.OwnerID.MarshalTo(dAtA[i:]); err != nil {
			return 0, err
		}
		i = encodeVarintTypes(dAtA, i, uint64(size))
	}
	i--
	dAtA[i] = 0xa
	return len(dAtA) - i, nil
}

func (m *AccessGroup) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *AccessGroup) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *AccessGroup) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.XXX_unrecognized != nil {
		i -= len(m.XXX_unrecognized)
		copy(dAtA[i:], m.XXX_unrecognized)
	}
	if len(m.UserGroup) > 0 {
		for iNdEx := len(m.UserGroup) - 1; iNdEx >= 0; iNdEx-- {
			{
				size := m.UserGroup[iNdEx].Size()
				i -= size
				if _, err := m.UserGroup[iNdEx].MarshalTo(dAtA[i:]); err != nil {
					return 0, err
				}
				i = encodeVarintTypes(dAtA, i, uint64(size))
			}
			i--
			dAtA[i] = 0x12
		}
	}
	if m.AccessMode != 0 {
		i = encodeVarintTypes(dAtA, i, uint64(m.AccessMode))
		i--
		dAtA[i] = 0x8
	}
	return len(dAtA) - i, nil
}

func (m *AccessControlList) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *AccessControlList) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *AccessControlList) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.XXX_unrecognized != nil {
		i -= len(m.XXX_unrecognized)
		copy(dAtA[i:], m.XXX_unrecognized)
	}
	if len(m.List) > 0 {
		for iNdEx := len(m.List) - 1; iNdEx >= 0; iNdEx-- {
			{
				size, err := m.List[iNdEx].MarshalToSizedBuffer(dAtA[:i])
				if err != nil {
					return 0, err
				}
				i -= size
				i = encodeVarintTypes(dAtA, i, uint64(size))
			}
			i--
			dAtA[i] = 0xa
		}
	}
	return len(dAtA) - i, nil
}

func encodeVarintTypes(dAtA []byte, offset int, v uint64) int {
	offset -= sovTypes(v)
	base := offset
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return base
}
func (m *Container) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = m.OwnerID.Size()
	n += 1 + l + sovTypes(uint64(l))
	l = m.Salt.Size()
	n += 1 + l + sovTypes(uint64(l))
	if m.Capacity != 0 {
		n += 1 + sovTypes(uint64(m.Capacity))
	}
	l = m.Rules.Size()
	n += 1 + l + sovTypes(uint64(l))
	l = m.List.Size()
	n += 1 + l + sovTypes(uint64(l))
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func (m *AccessGroup) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.AccessMode != 0 {
		n += 1 + sovTypes(uint64(m.AccessMode))
	}
	if len(m.UserGroup) > 0 {
		for _, e := range m.UserGroup {
			l = e.Size()
			n += 1 + l + sovTypes(uint64(l))
		}
	}
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func (m *AccessControlList) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if len(m.List) > 0 {
		for _, e := range m.List {
			l = e.Size()
			n += 1 + l + sovTypes(uint64(l))
		}
	}
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func sovTypes(x uint64) (n int) {
	return (math_bits.Len64(x|1) + 6) / 7
}
func sozTypes(x uint64) (n int) {
	return sovTypes(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *Container) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowTypes
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: Container: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: Container: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field OwnerID", wireType)
			}
			var byteLen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowTypes
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				byteLen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if byteLen < 0 {
				return ErrInvalidLengthTypes
			}
			postIndex := iNdEx + byteLen
			if postIndex < 0 {
				return ErrInvalidLengthTypes
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if err := m.OwnerID.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Salt", wireType)
			}
			var byteLen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowTypes
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				byteLen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if byteLen < 0 {
				return ErrInvalidLengthTypes
			}
			postIndex := iNdEx + byteLen
			if postIndex < 0 {
				return ErrInvalidLengthTypes
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if err := m.Salt.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 3:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Capacity", wireType)
			}
			m.Capacity = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowTypes
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.Capacity |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 4:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Rules", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowTypes
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthTypes
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthTypes
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if err := m.Rules.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 5:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field List", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowTypes
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthTypes
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthTypes
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if err := m.List.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipTypes(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthTypes
			}
			if (iNdEx + skippy) < 0 {
				return ErrInvalidLengthTypes
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			m.XXX_unrecognized = append(m.XXX_unrecognized, dAtA[iNdEx:iNdEx+skippy]...)
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *AccessGroup) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowTypes
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: AccessGroup: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: AccessGroup: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field AccessMode", wireType)
			}
			m.AccessMode = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowTypes
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.AccessMode |= uint32(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field UserGroup", wireType)
			}
			var byteLen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowTypes
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				byteLen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if byteLen < 0 {
				return ErrInvalidLengthTypes
			}
			postIndex := iNdEx + byteLen
			if postIndex < 0 {
				return ErrInvalidLengthTypes
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			var v OwnerID
			m.UserGroup = append(m.UserGroup, v)
			if err := m.UserGroup[len(m.UserGroup)-1].Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipTypes(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthTypes
			}
			if (iNdEx + skippy) < 0 {
				return ErrInvalidLengthTypes
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			m.XXX_unrecognized = append(m.XXX_unrecognized, dAtA[iNdEx:iNdEx+skippy]...)
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *AccessControlList) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowTypes
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: AccessControlList: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: AccessControlList: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field List", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowTypes
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthTypes
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthTypes
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.List = append(m.List, AccessGroup{})
			if err := m.List[len(m.List)-1].Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipTypes(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthTypes
			}
			if (iNdEx + skippy) < 0 {
				return ErrInvalidLengthTypes
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			m.XXX_unrecognized = append(m.XXX_unrecognized, dAtA[iNdEx:iNdEx+skippy]...)
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func skipTypes(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	depth := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowTypes
			}
			if iNdEx >= l {
				return 0, io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		wireType := int(wire & 0x7)
		switch wireType {
		case 0:
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowTypes
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				iNdEx++
				if dAtA[iNdEx-1] < 0x80 {
					break
				}
			}
		case 1:
			iNdEx += 8
		case 2:
			var length int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowTypes
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				length |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if length < 0 {
				return 0, ErrInvalidLengthTypes
			}
			iNdEx += length
		case 3:
			depth++
		case 4:
			if depth == 0 {
				return 0, ErrUnexpectedEndOfGroupTypes
			}
			depth--
		case 5:
			iNdEx += 4
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
		if iNdEx < 0 {
			return 0, ErrInvalidLengthTypes
		}
		if depth == 0 {
			return iNdEx, nil
		}
	}
	return 0, io.ErrUnexpectedEOF
}

var (
	ErrInvalidLengthTypes        = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowTypes          = fmt.Errorf("proto: integer overflow")
	ErrUnexpectedEndOfGroupTypes = fmt.Errorf("proto: unexpected end of group")
)
