// Code generated by protoc-gen-go-neofs. DO NOT EDIT.

package netmap

import "github.com/nspcc-dev/neofs-api-go/v2/util/proto"

func (x *LocalNodeInfoRequest_Body) StableSize() (size int) {
	if x == nil {
		return
	}
	return size
}

func (x *LocalNodeInfoRequest_Body) StableMarshal(buf []byte) ([]byte, error) {
	if x == nil {
		return []byte{}, nil
	}
	if buf == nil {
		buf = make([]byte, x.StableSize())
	}
	var err error
	var offset, n int
	_, _, _ = err, offset, n
	return buf, nil
}

func (x *LocalNodeInfoRequest) StableSize() (size int) {
	if x == nil {
		return
	}
	size += proto.NestedStructureSize(1, x.Body)
	size += proto.NestedStructureSize(2, x.MetaHeader)
	size += proto.NestedStructureSize(3, x.VerifyHeader)
	return size
}

func (x *LocalNodeInfoRequest) StableMarshal(buf []byte) ([]byte, error) {
	if x == nil {
		return []byte{}, nil
	}
	if buf == nil {
		buf = make([]byte, x.StableSize())
	}
	var err error
	var offset, n int
	_, _, _ = err, offset, n
	n, err = proto.NestedStructureMarshal(1, buf[offset:], x.Body)
	if err != nil {
		return nil, err
	}
	offset += n
	n, err = proto.NestedStructureMarshal(2, buf[offset:], x.MetaHeader)
	if err != nil {
		return nil, err
	}
	offset += n
	n, err = proto.NestedStructureMarshal(3, buf[offset:], x.VerifyHeader)
	if err != nil {
		return nil, err
	}
	offset += n
	return buf, nil
}

func (x *LocalNodeInfoResponse_Body) StableSize() (size int) {
	if x == nil {
		return
	}
	size += proto.NestedStructureSize(1, x.Version)
	size += proto.NestedStructureSize(2, x.NodeInfo)
	return size
}

func (x *LocalNodeInfoResponse_Body) StableMarshal(buf []byte) ([]byte, error) {
	if x == nil {
		return []byte{}, nil
	}
	if buf == nil {
		buf = make([]byte, x.StableSize())
	}
	var err error
	var offset, n int
	_, _, _ = err, offset, n
	n, err = proto.NestedStructureMarshal(1, buf[offset:], x.Version)
	if err != nil {
		return nil, err
	}
	offset += n
	n, err = proto.NestedStructureMarshal(2, buf[offset:], x.NodeInfo)
	if err != nil {
		return nil, err
	}
	offset += n
	return buf, nil
}

func (x *LocalNodeInfoResponse) StableSize() (size int) {
	if x == nil {
		return
	}
	size += proto.NestedStructureSize(1, x.Body)
	size += proto.NestedStructureSize(2, x.MetaHeader)
	size += proto.NestedStructureSize(3, x.VerifyHeader)
	return size
}

func (x *LocalNodeInfoResponse) StableMarshal(buf []byte) ([]byte, error) {
	if x == nil {
		return []byte{}, nil
	}
	if buf == nil {
		buf = make([]byte, x.StableSize())
	}
	var err error
	var offset, n int
	_, _, _ = err, offset, n
	n, err = proto.NestedStructureMarshal(1, buf[offset:], x.Body)
	if err != nil {
		return nil, err
	}
	offset += n
	n, err = proto.NestedStructureMarshal(2, buf[offset:], x.MetaHeader)
	if err != nil {
		return nil, err
	}
	offset += n
	n, err = proto.NestedStructureMarshal(3, buf[offset:], x.VerifyHeader)
	if err != nil {
		return nil, err
	}
	offset += n
	return buf, nil
}

func (x *NetworkInfoRequest_Body) StableSize() (size int) {
	if x == nil {
		return
	}
	return size
}

func (x *NetworkInfoRequest_Body) StableMarshal(buf []byte) ([]byte, error) {
	if x == nil {
		return []byte{}, nil
	}
	if buf == nil {
		buf = make([]byte, x.StableSize())
	}
	var err error
	var offset, n int
	_, _, _ = err, offset, n
	return buf, nil
}

func (x *NetworkInfoRequest) StableSize() (size int) {
	if x == nil {
		return
	}
	size += proto.NestedStructureSize(1, x.Body)
	size += proto.NestedStructureSize(2, x.MetaHeader)
	size += proto.NestedStructureSize(3, x.VerifyHeader)
	return size
}

func (x *NetworkInfoRequest) StableMarshal(buf []byte) ([]byte, error) {
	if x == nil {
		return []byte{}, nil
	}
	if buf == nil {
		buf = make([]byte, x.StableSize())
	}
	var err error
	var offset, n int
	_, _, _ = err, offset, n
	n, err = proto.NestedStructureMarshal(1, buf[offset:], x.Body)
	if err != nil {
		return nil, err
	}
	offset += n
	n, err = proto.NestedStructureMarshal(2, buf[offset:], x.MetaHeader)
	if err != nil {
		return nil, err
	}
	offset += n
	n, err = proto.NestedStructureMarshal(3, buf[offset:], x.VerifyHeader)
	if err != nil {
		return nil, err
	}
	offset += n
	return buf, nil
}

func (x *NetworkInfoResponse_Body) StableSize() (size int) {
	if x == nil {
		return
	}
	size += proto.NestedStructureSize(1, x.NetworkInfo)
	return size
}

func (x *NetworkInfoResponse_Body) StableMarshal(buf []byte) ([]byte, error) {
	if x == nil {
		return []byte{}, nil
	}
	if buf == nil {
		buf = make([]byte, x.StableSize())
	}
	var err error
	var offset, n int
	_, _, _ = err, offset, n
	n, err = proto.NestedStructureMarshal(1, buf[offset:], x.NetworkInfo)
	if err != nil {
		return nil, err
	}
	offset += n
	return buf, nil
}

func (x *NetworkInfoResponse) StableSize() (size int) {
	if x == nil {
		return
	}
	size += proto.NestedStructureSize(1, x.Body)
	size += proto.NestedStructureSize(2, x.MetaHeader)
	size += proto.NestedStructureSize(3, x.VerifyHeader)
	return size
}

func (x *NetworkInfoResponse) StableMarshal(buf []byte) ([]byte, error) {
	if x == nil {
		return []byte{}, nil
	}
	if buf == nil {
		buf = make([]byte, x.StableSize())
	}
	var err error
	var offset, n int
	_, _, _ = err, offset, n
	n, err = proto.NestedStructureMarshal(1, buf[offset:], x.Body)
	if err != nil {
		return nil, err
	}
	offset += n
	n, err = proto.NestedStructureMarshal(2, buf[offset:], x.MetaHeader)
	if err != nil {
		return nil, err
	}
	offset += n
	n, err = proto.NestedStructureMarshal(3, buf[offset:], x.VerifyHeader)
	if err != nil {
		return nil, err
	}
	offset += n
	return buf, nil
}
