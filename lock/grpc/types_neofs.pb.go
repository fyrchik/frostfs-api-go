// Code generated by protoc-gen-go-neofs. DO NOT EDIT.

package lock

import "github.com/nspcc-dev/neofs-api-go/v2/util/proto"

func (x *Lock) StableSize() (size int) {
	if x == nil {
		return
	}
	for i := range x.Members {
		size += proto.NestedStructureSize(1, x.Members[i])
	}
	return size
}

func (x *Lock) StableMarshal(buf []byte) ([]byte, error) {
	if x == nil {
		return []byte{}, nil
	}
	if buf == nil {
		buf = make([]byte, x.StableSize())
	}
	var err error
	var offset, n int
	_, _, _ = err, offset, n
	for i := range x.Members {
		n, err = proto.NestedStructureMarshal(1, buf[offset:], x.Members[i])
		if err != nil {
			return nil, err
		}
		offset += n
	}
	return buf, nil
}
