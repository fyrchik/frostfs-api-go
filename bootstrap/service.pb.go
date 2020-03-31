// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: bootstrap/service.proto

package bootstrap

import (
	context "context"
	fmt "fmt"
	_ "github.com/gogo/protobuf/gogoproto"
	proto "github.com/golang/protobuf/proto"
	service "github.com/nspcc-dev/neofs-api-go/service"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
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

type Request struct {
	// Type is NodeType, can be InnerRingNode (type=1) or StorageNode (type=2)
	Type NodeType `protobuf:"varint,1,opt,name=type,proto3,customtype=NodeType" json:"type"`
	// Info contains information about node
	Info NodeInfo `protobuf:"bytes,2,opt,name=info,proto3" json:"info"`
	// RequestMetaHeader contains information about request meta headers (should be embedded into message)
	service.RequestMetaHeader `protobuf:"bytes,98,opt,name=Meta,proto3,embedded=Meta" json:"Meta"`
	// RequestVerificationHeader is a set of signatures of every NeoFS Node that processed request (should be embedded into message)
	service.RequestVerificationHeader `protobuf:"bytes,99,opt,name=Verify,proto3,embedded=Verify" json:"Verify"`
	XXX_NoUnkeyedLiteral              struct{} `json:"-"`
	XXX_unrecognized                  []byte   `json:"-"`
	XXX_sizecache                     int32    `json:"-"`
}

func (m *Request) Reset()         { *m = Request{} }
func (m *Request) String() string { return proto.CompactTextString(m) }
func (*Request) ProtoMessage()    {}
func (*Request) Descriptor() ([]byte, []int) {
	return fileDescriptor_21bce759c9d8eb63, []int{0}
}
func (m *Request) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *Request) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	b = b[:cap(b)]
	n, err := m.MarshalToSizedBuffer(b)
	if err != nil {
		return nil, err
	}
	return b[:n], nil
}
func (m *Request) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Request.Merge(m, src)
}
func (m *Request) XXX_Size() int {
	return m.Size()
}
func (m *Request) XXX_DiscardUnknown() {
	xxx_messageInfo_Request.DiscardUnknown(m)
}

var xxx_messageInfo_Request proto.InternalMessageInfo

func (m *Request) GetInfo() NodeInfo {
	if m != nil {
		return m.Info
	}
	return NodeInfo{}
}

func init() {
	proto.RegisterType((*Request)(nil), "bootstrap.Request")
}

func init() { proto.RegisterFile("bootstrap/service.proto", fileDescriptor_21bce759c9d8eb63) }

var fileDescriptor_21bce759c9d8eb63 = []byte{
	// 364 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x64, 0x51, 0xbf, 0x6e, 0x9b, 0x40,
	0x18, 0xf7, 0x59, 0xd4, 0x7f, 0xae, 0xdb, 0xd9, 0x55, 0x11, 0x03, 0x58, 0x9e, 0x2c, 0xb5, 0x80,
	0x64, 0x2f, 0x1d, 0x5b, 0x54, 0x55, 0xf5, 0x60, 0xcb, 0xc2, 0x55, 0x23, 0x65, 0x3b, 0xe0, 0x83,
	0x30, 0x98, 0xbb, 0x70, 0x67, 0x4b, 0x7e, 0x93, 0x3c, 0x43, 0x9e, 0xc4, 0xa3, 0xc7, 0x28, 0x03,
	0x8a, 0x88, 0x94, 0xe7, 0x88, 0x38, 0x63, 0x62, 0x25, 0x13, 0x7c, 0xbf, 0x7f, 0xf7, 0xbb, 0xef,
	0xf0, 0xd7, 0x80, 0x31, 0x29, 0x64, 0x4e, 0xb9, 0x2b, 0x20, 0xdf, 0xa5, 0x21, 0x38, 0x3c, 0x67,
	0x92, 0x91, 0x7e, 0x43, 0x18, 0xa4, 0x66, 0xdc, 0x0d, 0x48, 0x7a, 0xa2, 0x8d, 0xe1, 0x19, 0xdb,
	0x41, 0x9e, 0xc6, 0xfb, 0x1a, 0xfd, 0xf2, 0x96, 0x26, 0xf7, 0x1c, 0x44, 0x0d, 0xdb, 0x49, 0x2a,
	0x6f, 0xb6, 0x81, 0x13, 0xb2, 0x8d, 0x9b, 0xb0, 0x84, 0xb9, 0x0a, 0x0e, 0xb6, 0xb1, 0x9a, 0xd4,
	0xa0, 0xfe, 0x4e, 0xf2, 0xf1, 0x0b, 0xc2, 0x5d, 0x1f, 0x6e, 0xb7, 0x20, 0x24, 0xf9, 0x8e, 0xb5,
	0x2a, 0x49, 0x47, 0x23, 0x34, 0xf9, 0xe4, 0xe9, 0x87, 0xc2, 0x6a, 0x3d, 0x16, 0x56, 0x6f, 0xc9,
	0x22, 0xf8, 0xb7, 0xe7, 0x50, 0x16, 0x96, 0x56, 0x7d, 0x7d, 0xa5, 0x22, 0x36, 0xd6, 0xd2, 0x2c,
	0x66, 0x7a, 0x7b, 0x84, 0x26, 0x9f, 0xa7, 0x03, 0xa7, 0xa9, 0xe3, 0x54, 0x86, 0x79, 0x16, 0x33,
	0x4f, 0xab, 0x22, 0x7c, 0x25, 0x23, 0x3f, 0xb0, 0xb6, 0x00, 0x49, 0xf5, 0x40, 0xc9, 0x0d, 0xe7,
	0xbc, 0x81, 0xfa, 0xf0, 0x8a, 0xfb, 0x0b, 0x34, 0x82, 0xdc, 0xeb, 0x55, 0xae, 0x63, 0x61, 0x21,
	0x5f, 0x39, 0xc8, 0x6f, 0xdc, 0xf9, 0xaf, 0x2e, 0xae, 0x87, 0xca, 0x3b, 0x7e, 0xef, 0x55, 0x6c,
	0x1a, 0x52, 0x99, 0xb2, 0xec, 0x43, 0x46, 0xed, 0x9d, 0xfe, 0xc4, 0x7d, 0xef, 0xdc, 0x90, 0xcc,
	0x70, 0x77, 0x95, 0xb3, 0x10, 0x84, 0x20, 0xe4, 0xa2, 0x78, 0x9d, 0x67, 0x0c, 0x2f, 0xb0, 0x35,
	0xcf, 0x81, 0x46, 0x0b, 0xca, 0xbd, 0xab, 0x43, 0x69, 0xa2, 0x63, 0x69, 0xa2, 0x87, 0xd2, 0x44,
	0x4f, 0xa5, 0x89, 0xee, 0x9e, 0xcd, 0xd6, 0xf5, 0xb7, 0x8b, 0x7d, 0x67, 0x82, 0x87, 0xa1, 0x1d,
	0xc1, 0xce, 0xcd, 0x80, 0xc5, 0xc2, 0xa6, 0x3c, 0xb5, 0x13, 0xe6, 0x36, 0x61, 0xf7, 0xed, 0xc1,
	0x12, 0xd8, 0x9f, 0xb5, 0xf3, 0x6b, 0x35, 0x77, 0x9a, 0x36, 0x41, 0x47, 0x3d, 0xc5, 0xec, 0x35,
	0x00, 0x00, 0xff, 0xff, 0xc7, 0x01, 0xac, 0x62, 0x20, 0x02, 0x00, 0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// BootstrapClient is the client API for Bootstrap service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type BootstrapClient interface {
	// Process is method that allows to register node in the network and receive actual netmap
	Process(ctx context.Context, in *Request, opts ...grpc.CallOption) (*SpreadMap, error)
}

type bootstrapClient struct {
	cc *grpc.ClientConn
}

func NewBootstrapClient(cc *grpc.ClientConn) BootstrapClient {
	return &bootstrapClient{cc}
}

func (c *bootstrapClient) Process(ctx context.Context, in *Request, opts ...grpc.CallOption) (*SpreadMap, error) {
	out := new(SpreadMap)
	err := c.cc.Invoke(ctx, "/bootstrap.Bootstrap/Process", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// BootstrapServer is the server API for Bootstrap service.
type BootstrapServer interface {
	// Process is method that allows to register node in the network and receive actual netmap
	Process(context.Context, *Request) (*SpreadMap, error)
}

// UnimplementedBootstrapServer can be embedded to have forward compatible implementations.
type UnimplementedBootstrapServer struct {
}

func (*UnimplementedBootstrapServer) Process(ctx context.Context, req *Request) (*SpreadMap, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Process not implemented")
}

func RegisterBootstrapServer(s *grpc.Server, srv BootstrapServer) {
	s.RegisterService(&_Bootstrap_serviceDesc, srv)
}

func _Bootstrap_Process_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Request)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(BootstrapServer).Process(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/bootstrap.Bootstrap/Process",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(BootstrapServer).Process(ctx, req.(*Request))
	}
	return interceptor(ctx, in, info, handler)
}

var _Bootstrap_serviceDesc = grpc.ServiceDesc{
	ServiceName: "bootstrap.Bootstrap",
	HandlerType: (*BootstrapServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Process",
			Handler:    _Bootstrap_Process_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "bootstrap/service.proto",
}

func (m *Request) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *Request) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *Request) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.XXX_unrecognized != nil {
		i -= len(m.XXX_unrecognized)
		copy(dAtA[i:], m.XXX_unrecognized)
	}
	{
		size, err := m.RequestVerificationHeader.MarshalToSizedBuffer(dAtA[:i])
		if err != nil {
			return 0, err
		}
		i -= size
		i = encodeVarintService(dAtA, i, uint64(size))
	}
	i--
	dAtA[i] = 0x6
	i--
	dAtA[i] = 0x9a
	{
		size, err := m.RequestMetaHeader.MarshalToSizedBuffer(dAtA[:i])
		if err != nil {
			return 0, err
		}
		i -= size
		i = encodeVarintService(dAtA, i, uint64(size))
	}
	i--
	dAtA[i] = 0x6
	i--
	dAtA[i] = 0x92
	{
		size, err := m.Info.MarshalToSizedBuffer(dAtA[:i])
		if err != nil {
			return 0, err
		}
		i -= size
		i = encodeVarintService(dAtA, i, uint64(size))
	}
	i--
	dAtA[i] = 0x12
	if m.Type != 0 {
		i = encodeVarintService(dAtA, i, uint64(m.Type))
		i--
		dAtA[i] = 0x8
	}
	return len(dAtA) - i, nil
}

func encodeVarintService(dAtA []byte, offset int, v uint64) int {
	offset -= sovService(v)
	base := offset
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return base
}
func (m *Request) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.Type != 0 {
		n += 1 + sovService(uint64(m.Type))
	}
	l = m.Info.Size()
	n += 1 + l + sovService(uint64(l))
	l = m.RequestMetaHeader.Size()
	n += 2 + l + sovService(uint64(l))
	l = m.RequestVerificationHeader.Size()
	n += 2 + l + sovService(uint64(l))
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func sovService(x uint64) (n int) {
	return (math_bits.Len64(x|1) + 6) / 7
}
func sozService(x uint64) (n int) {
	return sovService(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *Request) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowService
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
			return fmt.Errorf("proto: Request: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: Request: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Type", wireType)
			}
			m.Type = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowService
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.Type |= NodeType(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Info", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowService
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
				return ErrInvalidLengthService
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthService
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if err := m.Info.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 98:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field RequestMetaHeader", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowService
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
				return ErrInvalidLengthService
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthService
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if err := m.RequestMetaHeader.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 99:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field RequestVerificationHeader", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowService
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
				return ErrInvalidLengthService
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthService
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if err := m.RequestVerificationHeader.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipService(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthService
			}
			if (iNdEx + skippy) < 0 {
				return ErrInvalidLengthService
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
func skipService(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	depth := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowService
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
					return 0, ErrIntOverflowService
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
					return 0, ErrIntOverflowService
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
				return 0, ErrInvalidLengthService
			}
			iNdEx += length
		case 3:
			depth++
		case 4:
			if depth == 0 {
				return 0, ErrUnexpectedEndOfGroupService
			}
			depth--
		case 5:
			iNdEx += 4
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
		if iNdEx < 0 {
			return 0, ErrInvalidLengthService
		}
		if depth == 0 {
			return iNdEx, nil
		}
	}
	return 0, io.ErrUnexpectedEOF
}

var (
	ErrInvalidLengthService        = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowService          = fmt.Errorf("proto: integer overflow")
	ErrUnexpectedEndOfGroupService = fmt.Errorf("proto: unexpected end of group")
)
