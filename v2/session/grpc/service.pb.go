// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: v2/session/grpc/service.proto

package session

import (
	context "context"
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	grpc "github.com/nspcc-dev/neofs-api-go/v2/refs/grpc"
	grpc1 "google.golang.org/grpc"
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

// Information necessary for opening a session.
type CreateRequest struct {
	// Body of create session token request message.
	Body *CreateRequest_Body `protobuf:"bytes,1,opt,name=body,proto3" json:"body,omitempty"`
	// Carries request meta information. Header data is used only to regulate
	// message transport and does not affect request execution.
	MetaHeader *RequestMetaHeader `protobuf:"bytes,2,opt,name=meta_header,json=metaHeader,proto3" json:"meta_header,omitempty"`
	// Carries request verification information. This header is used to
	// authenticate the nodes of the message route and check the correctness of
	// transmission.
	VerifyHeader         *RequestVerificationHeader `protobuf:"bytes,3,opt,name=verify_header,json=verifyHeader,proto3" json:"verify_header,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                   `json:"-"`
	XXX_unrecognized     []byte                     `json:"-"`
	XXX_sizecache        int32                      `json:"-"`
}

func (m *CreateRequest) Reset()         { *m = CreateRequest{} }
func (m *CreateRequest) String() string { return proto.CompactTextString(m) }
func (*CreateRequest) ProtoMessage()    {}
func (*CreateRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_4ed1365cc8e16cd4, []int{0}
}
func (m *CreateRequest) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *CreateRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_CreateRequest.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *CreateRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_CreateRequest.Merge(m, src)
}
func (m *CreateRequest) XXX_Size() int {
	return m.Size()
}
func (m *CreateRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_CreateRequest.DiscardUnknown(m)
}

var xxx_messageInfo_CreateRequest proto.InternalMessageInfo

func (m *CreateRequest) GetBody() *CreateRequest_Body {
	if m != nil {
		return m.Body
	}
	return nil
}

func (m *CreateRequest) GetMetaHeader() *RequestMetaHeader {
	if m != nil {
		return m.MetaHeader
	}
	return nil
}

func (m *CreateRequest) GetVerifyHeader() *RequestVerificationHeader {
	if m != nil {
		return m.VerifyHeader
	}
	return nil
}

// Session creation request body
type CreateRequest_Body struct {
	// Dession initiating user's or node's key derived `OwnerID`.
	OwnerId *grpc.OwnerID `protobuf:"bytes,1,opt,name=owner_id,json=ownerId,proto3" json:"owner_id,omitempty"`
	// Session expiration `Epoch`
	Expiration           uint64   `protobuf:"varint,2,opt,name=expiration,proto3" json:"expiration,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *CreateRequest_Body) Reset()         { *m = CreateRequest_Body{} }
func (m *CreateRequest_Body) String() string { return proto.CompactTextString(m) }
func (*CreateRequest_Body) ProtoMessage()    {}
func (*CreateRequest_Body) Descriptor() ([]byte, []int) {
	return fileDescriptor_4ed1365cc8e16cd4, []int{0, 0}
}
func (m *CreateRequest_Body) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *CreateRequest_Body) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_CreateRequest_Body.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *CreateRequest_Body) XXX_Merge(src proto.Message) {
	xxx_messageInfo_CreateRequest_Body.Merge(m, src)
}
func (m *CreateRequest_Body) XXX_Size() int {
	return m.Size()
}
func (m *CreateRequest_Body) XXX_DiscardUnknown() {
	xxx_messageInfo_CreateRequest_Body.DiscardUnknown(m)
}

var xxx_messageInfo_CreateRequest_Body proto.InternalMessageInfo

func (m *CreateRequest_Body) GetOwnerId() *grpc.OwnerID {
	if m != nil {
		return m.OwnerId
	}
	return nil
}

func (m *CreateRequest_Body) GetExpiration() uint64 {
	if m != nil {
		return m.Expiration
	}
	return 0
}

// Information about the opened session.
type CreateResponse struct {
	// Body of create session token response message.
	Body *CreateResponse_Body `protobuf:"bytes,1,opt,name=body,proto3" json:"body,omitempty"`
	// Carries response meta information. Header data is used only to regulate
	// message transport and does not affect request execution.
	MetaHeader *ResponseMetaHeader `protobuf:"bytes,2,opt,name=meta_header,json=metaHeader,proto3" json:"meta_header,omitempty"`
	// Carries response verification information. This header is used to
	// authenticate the nodes of the message route and check the correctness of
	// transmission.
	VerifyHeader         *ResponseVerificationHeader `protobuf:"bytes,3,opt,name=verify_header,json=verifyHeader,proto3" json:"verify_header,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                    `json:"-"`
	XXX_unrecognized     []byte                      `json:"-"`
	XXX_sizecache        int32                       `json:"-"`
}

func (m *CreateResponse) Reset()         { *m = CreateResponse{} }
func (m *CreateResponse) String() string { return proto.CompactTextString(m) }
func (*CreateResponse) ProtoMessage()    {}
func (*CreateResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_4ed1365cc8e16cd4, []int{1}
}
func (m *CreateResponse) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *CreateResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_CreateResponse.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *CreateResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_CreateResponse.Merge(m, src)
}
func (m *CreateResponse) XXX_Size() int {
	return m.Size()
}
func (m *CreateResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_CreateResponse.DiscardUnknown(m)
}

var xxx_messageInfo_CreateResponse proto.InternalMessageInfo

func (m *CreateResponse) GetBody() *CreateResponse_Body {
	if m != nil {
		return m.Body
	}
	return nil
}

func (m *CreateResponse) GetMetaHeader() *ResponseMetaHeader {
	if m != nil {
		return m.MetaHeader
	}
	return nil
}

func (m *CreateResponse) GetVerifyHeader() *ResponseVerificationHeader {
	if m != nil {
		return m.VerifyHeader
	}
	return nil
}

// Session creation response body
type CreateResponse_Body struct {
	// Identifier of a newly created session
	Id []byte `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	// Public key used for session
	SessionKey           []byte   `protobuf:"bytes,2,opt,name=session_key,json=sessionKey,proto3" json:"session_key,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *CreateResponse_Body) Reset()         { *m = CreateResponse_Body{} }
func (m *CreateResponse_Body) String() string { return proto.CompactTextString(m) }
func (*CreateResponse_Body) ProtoMessage()    {}
func (*CreateResponse_Body) Descriptor() ([]byte, []int) {
	return fileDescriptor_4ed1365cc8e16cd4, []int{1, 0}
}
func (m *CreateResponse_Body) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *CreateResponse_Body) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_CreateResponse_Body.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *CreateResponse_Body) XXX_Merge(src proto.Message) {
	xxx_messageInfo_CreateResponse_Body.Merge(m, src)
}
func (m *CreateResponse_Body) XXX_Size() int {
	return m.Size()
}
func (m *CreateResponse_Body) XXX_DiscardUnknown() {
	xxx_messageInfo_CreateResponse_Body.DiscardUnknown(m)
}

var xxx_messageInfo_CreateResponse_Body proto.InternalMessageInfo

func (m *CreateResponse_Body) GetId() []byte {
	if m != nil {
		return m.Id
	}
	return nil
}

func (m *CreateResponse_Body) GetSessionKey() []byte {
	if m != nil {
		return m.SessionKey
	}
	return nil
}

func init() {
	proto.RegisterType((*CreateRequest)(nil), "neo.fs.v2.session.CreateRequest")
	proto.RegisterType((*CreateRequest_Body)(nil), "neo.fs.v2.session.CreateRequest.Body")
	proto.RegisterType((*CreateResponse)(nil), "neo.fs.v2.session.CreateResponse")
	proto.RegisterType((*CreateResponse_Body)(nil), "neo.fs.v2.session.CreateResponse.Body")
}

func init() { proto.RegisterFile("v2/session/grpc/service.proto", fileDescriptor_4ed1365cc8e16cd4) }

var fileDescriptor_4ed1365cc8e16cd4 = []byte{
	// 444 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x84, 0x93, 0x4d, 0x6f, 0xd3, 0x30,
	0x18, 0xc7, 0x49, 0xa8, 0x06, 0x7a, 0xda, 0x55, 0xc2, 0x42, 0xa2, 0x2a, 0x22, 0x8c, 0x89, 0x21,
	0x0e, 0xd4, 0x91, 0xc2, 0x01, 0x0d, 0x4e, 0x0c, 0x98, 0xa8, 0xd0, 0x78, 0x71, 0x25, 0x0e, 0xbb,
	0x54, 0x79, 0x79, 0xd2, 0x59, 0xa8, 0x71, 0xb0, 0xbd, 0x40, 0xbe, 0x09, 0x57, 0xae, 0x7c, 0x0a,
	0x8e, 0x1c, 0xf9, 0x08, 0xa8, 0x7c, 0x11, 0x14, 0xdb, 0x43, 0xd9, 0x96, 0xad, 0xb7, 0x38, 0xfe,
	0x3f, 0x3f, 0x3f, 0xcf, 0x4f, 0x36, 0xdc, 0xa9, 0xa2, 0x50, 0xa1, 0x52, 0x5c, 0x14, 0xe1, 0x42,
	0x96, 0x69, 0xa8, 0x50, 0x56, 0x3c, 0x45, 0x5a, 0x4a, 0xa1, 0x05, 0xb9, 0x51, 0xa0, 0xa0, 0xb9,
	0xa2, 0x55, 0x44, 0x5d, 0x6a, 0x3c, 0xaa, 0xa2, 0x50, 0x62, 0xae, 0x6c, 0x5c, 0xd7, 0x25, 0x2a,
	0x1b, 0x1e, 0xdf, 0x3e, 0xcb, 0x6a, 0x6d, 0x6e, 0xff, 0xf4, 0x61, 0xf3, 0x85, 0xc4, 0x58, 0x23,
	0xc3, 0xcf, 0xc7, 0xa8, 0x34, 0xd9, 0x85, 0x5e, 0x22, 0xb2, 0x7a, 0xe4, 0x6d, 0x79, 0x0f, 0xfb,
	0xd1, 0x0e, 0x3d, 0x77, 0x14, 0x3d, 0x95, 0xa7, 0x7b, 0x22, 0xab, 0x99, 0x29, 0x21, 0xaf, 0xa0,
	0xbf, 0x44, 0x1d, 0xcf, 0x8f, 0x30, 0xce, 0x50, 0x8e, 0x7c, 0x43, 0xb8, 0xdf, 0x41, 0x70, 0xb5,
	0x07, 0xa8, 0xe3, 0xd7, 0x26, 0xcb, 0x60, 0xf9, 0xff, 0x9b, 0x7c, 0x80, 0xcd, 0x0a, 0x25, 0xcf,
	0xeb, 0x13, 0xd0, 0x55, 0x03, 0x7a, 0x74, 0x31, 0xe8, 0x63, 0x13, 0xe7, 0x69, 0xac, 0xb9, 0x28,
	0x1c, 0x70, 0x60, 0x11, 0x76, 0x35, 0x3e, 0x84, 0x5e, 0xd3, 0x27, 0x89, 0xe0, 0xba, 0xf8, 0x52,
	0xa0, 0x9c, 0xf3, 0xcc, 0x0d, 0x78, 0xab, 0x45, 0x6d, 0xfc, 0xd1, 0x77, 0xcd, 0xfe, 0xf4, 0x25,
	0xbb, 0x66, 0x82, 0xd3, 0x8c, 0x04, 0x00, 0xf8, 0xb5, 0xe4, 0xd2, 0xd0, 0xcd, 0x50, 0x3d, 0xd6,
	0xfa, 0xb3, 0xfd, 0xdd, 0x87, 0xe1, 0x89, 0x12, 0x55, 0x8a, 0x42, 0x21, 0x79, 0x7a, 0xca, 0xe1,
	0x83, 0x4b, 0x1c, 0xda, 0x82, 0xb6, 0xc4, 0xfd, 0x2e, 0x89, 0x3b, 0x9d, 0xb3, 0xdb, 0xe2, 0x0b,
	0x2c, 0xb2, 0x6e, 0x8b, 0x93, 0x4b, 0x48, 0x6b, 0x35, 0x3e, 0x71, 0x1a, 0x87, 0xe0, 0x3b, 0x81,
	0x03, 0xe6, 0xf3, 0x8c, 0xdc, 0x85, 0xbe, 0x63, 0xcd, 0x3f, 0x61, 0x6d, 0x7a, 0x1e, 0x30, 0x70,
	0xbf, 0xde, 0x60, 0x1d, 0xcd, 0x61, 0x38, 0xb3, 0xab, 0x99, 0xbd, 0xc8, 0xe4, 0x00, 0x36, 0xac,
	0x03, 0xb2, 0xb5, 0xee, 0x8a, 0x8d, 0xef, 0xad, 0x15, 0xb8, 0x97, 0xfc, 0x5a, 0x05, 0xde, 0xef,
	0x55, 0xe0, 0xfd, 0x59, 0x05, 0xde, 0xb7, 0xbf, 0xc1, 0x95, 0xc3, 0xdd, 0x05, 0xd7, 0x47, 0xc7,
	0x09, 0x4d, 0xc5, 0x32, 0x2c, 0x54, 0x99, 0xa6, 0x93, 0x0c, 0xab, 0xb0, 0x40, 0x91, 0xab, 0x49,
	0x5c, 0xf2, 0xc9, 0x42, 0x84, 0x67, 0x1e, 0xc6, 0x33, 0xb7, 0xf8, 0xe1, 0xdf, 0x7c, 0x8b, 0x62,
	0x7f, 0x46, 0x9f, 0xbf, 0x9f, 0x36, 0x47, 0xba, 0xce, 0x93, 0x0d, 0xf3, 0x64, 0x1e, 0xff, 0x0b,
	0x00, 0x00, 0xff, 0xff, 0xd3, 0xaa, 0x38, 0x65, 0x9d, 0x03, 0x00, 0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc1.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc1.SupportPackageIsVersion4

// SessionServiceClient is the client API for SessionService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type SessionServiceClient interface {
	// Opens a new session between two peers.
	Create(ctx context.Context, in *CreateRequest, opts ...grpc1.CallOption) (*CreateResponse, error)
}

type sessionServiceClient struct {
	cc *grpc1.ClientConn
}

func NewSessionServiceClient(cc *grpc1.ClientConn) SessionServiceClient {
	return &sessionServiceClient{cc}
}

func (c *sessionServiceClient) Create(ctx context.Context, in *CreateRequest, opts ...grpc1.CallOption) (*CreateResponse, error) {
	out := new(CreateResponse)
	err := c.cc.Invoke(ctx, "/neo.fs.v2.session.SessionService/Create", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// SessionServiceServer is the server API for SessionService service.
type SessionServiceServer interface {
	// Opens a new session between two peers.
	Create(context.Context, *CreateRequest) (*CreateResponse, error)
}

// UnimplementedSessionServiceServer can be embedded to have forward compatible implementations.
type UnimplementedSessionServiceServer struct {
}

func (*UnimplementedSessionServiceServer) Create(ctx context.Context, req *CreateRequest) (*CreateResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Create not implemented")
}

func RegisterSessionServiceServer(s *grpc1.Server, srv SessionServiceServer) {
	s.RegisterService(&_SessionService_serviceDesc, srv)
}

func _SessionService_Create_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc1.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SessionServiceServer).Create(ctx, in)
	}
	info := &grpc1.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/neo.fs.v2.session.SessionService/Create",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SessionServiceServer).Create(ctx, req.(*CreateRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _SessionService_serviceDesc = grpc1.ServiceDesc{
	ServiceName: "neo.fs.v2.session.SessionService",
	HandlerType: (*SessionServiceServer)(nil),
	Methods: []grpc1.MethodDesc{
		{
			MethodName: "Create",
			Handler:    _SessionService_Create_Handler,
		},
	},
	Streams:  []grpc1.StreamDesc{},
	Metadata: "v2/session/grpc/service.proto",
}

func (m *CreateRequest) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *CreateRequest) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *CreateRequest) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.XXX_unrecognized != nil {
		i -= len(m.XXX_unrecognized)
		copy(dAtA[i:], m.XXX_unrecognized)
	}
	if m.VerifyHeader != nil {
		{
			size, err := m.VerifyHeader.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintService(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0x1a
	}
	if m.MetaHeader != nil {
		{
			size, err := m.MetaHeader.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintService(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0x12
	}
	if m.Body != nil {
		{
			size, err := m.Body.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintService(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func (m *CreateRequest_Body) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *CreateRequest_Body) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *CreateRequest_Body) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.XXX_unrecognized != nil {
		i -= len(m.XXX_unrecognized)
		copy(dAtA[i:], m.XXX_unrecognized)
	}
	if m.Expiration != 0 {
		i = encodeVarintService(dAtA, i, uint64(m.Expiration))
		i--
		dAtA[i] = 0x10
	}
	if m.OwnerId != nil {
		{
			size, err := m.OwnerId.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintService(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func (m *CreateResponse) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *CreateResponse) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *CreateResponse) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.XXX_unrecognized != nil {
		i -= len(m.XXX_unrecognized)
		copy(dAtA[i:], m.XXX_unrecognized)
	}
	if m.VerifyHeader != nil {
		{
			size, err := m.VerifyHeader.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintService(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0x1a
	}
	if m.MetaHeader != nil {
		{
			size, err := m.MetaHeader.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintService(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0x12
	}
	if m.Body != nil {
		{
			size, err := m.Body.MarshalToSizedBuffer(dAtA[:i])
			if err != nil {
				return 0, err
			}
			i -= size
			i = encodeVarintService(dAtA, i, uint64(size))
		}
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func (m *CreateResponse_Body) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *CreateResponse_Body) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *CreateResponse_Body) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.XXX_unrecognized != nil {
		i -= len(m.XXX_unrecognized)
		copy(dAtA[i:], m.XXX_unrecognized)
	}
	if len(m.SessionKey) > 0 {
		i -= len(m.SessionKey)
		copy(dAtA[i:], m.SessionKey)
		i = encodeVarintService(dAtA, i, uint64(len(m.SessionKey)))
		i--
		dAtA[i] = 0x12
	}
	if len(m.Id) > 0 {
		i -= len(m.Id)
		copy(dAtA[i:], m.Id)
		i = encodeVarintService(dAtA, i, uint64(len(m.Id)))
		i--
		dAtA[i] = 0xa
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
func (m *CreateRequest) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.Body != nil {
		l = m.Body.Size()
		n += 1 + l + sovService(uint64(l))
	}
	if m.MetaHeader != nil {
		l = m.MetaHeader.Size()
		n += 1 + l + sovService(uint64(l))
	}
	if m.VerifyHeader != nil {
		l = m.VerifyHeader.Size()
		n += 1 + l + sovService(uint64(l))
	}
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func (m *CreateRequest_Body) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.OwnerId != nil {
		l = m.OwnerId.Size()
		n += 1 + l + sovService(uint64(l))
	}
	if m.Expiration != 0 {
		n += 1 + sovService(uint64(m.Expiration))
	}
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func (m *CreateResponse) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if m.Body != nil {
		l = m.Body.Size()
		n += 1 + l + sovService(uint64(l))
	}
	if m.MetaHeader != nil {
		l = m.MetaHeader.Size()
		n += 1 + l + sovService(uint64(l))
	}
	if m.VerifyHeader != nil {
		l = m.VerifyHeader.Size()
		n += 1 + l + sovService(uint64(l))
	}
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func (m *CreateResponse_Body) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.Id)
	if l > 0 {
		n += 1 + l + sovService(uint64(l))
	}
	l = len(m.SessionKey)
	if l > 0 {
		n += 1 + l + sovService(uint64(l))
	}
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
func (m *CreateRequest) Unmarshal(dAtA []byte) error {
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
			return fmt.Errorf("proto: CreateRequest: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: CreateRequest: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Body", wireType)
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
			if m.Body == nil {
				m.Body = &CreateRequest_Body{}
			}
			if err := m.Body.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field MetaHeader", wireType)
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
			if m.MetaHeader == nil {
				m.MetaHeader = &RequestMetaHeader{}
			}
			if err := m.MetaHeader.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field VerifyHeader", wireType)
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
			if m.VerifyHeader == nil {
				m.VerifyHeader = &RequestVerificationHeader{}
			}
			if err := m.VerifyHeader.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
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
func (m *CreateRequest_Body) Unmarshal(dAtA []byte) error {
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
			return fmt.Errorf("proto: Body: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: Body: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field OwnerId", wireType)
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
			if m.OwnerId == nil {
				m.OwnerId = &grpc.OwnerID{}
			}
			if err := m.OwnerId.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 2:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Expiration", wireType)
			}
			m.Expiration = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowService
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.Expiration |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
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
func (m *CreateResponse) Unmarshal(dAtA []byte) error {
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
			return fmt.Errorf("proto: CreateResponse: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: CreateResponse: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Body", wireType)
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
			if m.Body == nil {
				m.Body = &CreateResponse_Body{}
			}
			if err := m.Body.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field MetaHeader", wireType)
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
			if m.MetaHeader == nil {
				m.MetaHeader = &ResponseMetaHeader{}
			}
			if err := m.MetaHeader.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field VerifyHeader", wireType)
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
			if m.VerifyHeader == nil {
				m.VerifyHeader = &ResponseVerificationHeader{}
			}
			if err := m.VerifyHeader.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
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
func (m *CreateResponse_Body) Unmarshal(dAtA []byte) error {
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
			return fmt.Errorf("proto: Body: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: Body: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Id", wireType)
			}
			var byteLen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowService
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
				return ErrInvalidLengthService
			}
			postIndex := iNdEx + byteLen
			if postIndex < 0 {
				return ErrInvalidLengthService
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Id = append(m.Id[:0], dAtA[iNdEx:postIndex]...)
			if m.Id == nil {
				m.Id = []byte{}
			}
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field SessionKey", wireType)
			}
			var byteLen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowService
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
				return ErrInvalidLengthService
			}
			postIndex := iNdEx + byteLen
			if postIndex < 0 {
				return ErrInvalidLengthService
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.SessionKey = append(m.SessionKey[:0], dAtA[iNdEx:postIndex]...)
			if m.SessionKey == nil {
				m.SessionKey = []byte{}
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
