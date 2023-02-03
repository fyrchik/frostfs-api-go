package signature

import "github.com/TrueCloudLab/frostfs-api-go/v2/refs"

type StableMarshaler interface {
	StableMarshal([]byte) []byte
	StableSize() int
}

type DataSource interface {
	ReadSignedData([]byte) ([]byte, error)
	SignedDataSize() int
}

type DataWithSignature interface {
	DataSource
	GetSignature() *refs.Signature
	SetSignature(*refs.Signature)
}

func getBuffer(buf []byte, size int) []byte {
	if buf == nil || cap(buf) < size {
		return make([]byte, size)
	}
	return buf[:size]
}
