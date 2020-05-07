package object

import (
	"testing"

	"github.com/nspcc-dev/neofs-api-go/service"
	"github.com/nspcc-dev/neofs-crypto/test"
	"github.com/stretchr/testify/require"
)

func TestSignVerifyRequests(t *testing.T) {
	sk := test.DecodeKey(0)

	type sigType interface {
		service.SignedDataWithToken
		service.SignKeyPairAccumulator
		service.SignKeyPairSource
		SetToken(*Token)
	}

	items := []struct {
		constructor    func() sigType
		payloadCorrupt []func(sigType)
	}{
		{ // PutRequest.PutHeader
			constructor: func() sigType {
				return MakePutRequestHeader(new(Object))
			},
			payloadCorrupt: []func(sigType){
				func(s sigType) {
					obj := s.(*PutRequest).GetR().(*PutRequest_Header).Header.GetObject()
					obj.SystemHeader.PayloadLength++
				},
			},
		},
		{ // PutRequest.Chunk
			constructor: func() sigType {
				return MakePutRequestChunk(make([]byte, 10))
			},
			payloadCorrupt: []func(sigType){
				func(s sigType) {
					h := s.(*PutRequest).GetR().(*PutRequest_Chunk)
					h.Chunk[0]++
				},
			},
		},
		{ // GetRequest
			constructor: func() sigType {
				return new(GetRequest)
			},
			payloadCorrupt: []func(sigType){
				func(s sigType) {
					s.(*GetRequest).Address.CID[0]++
				},
				func(s sigType) {
					s.(*GetRequest).Address.ObjectID[0]++
				},
			},
		},
		{ // HeadRequest
			constructor: func() sigType {
				return new(HeadRequest)
			},
			payloadCorrupt: []func(sigType){
				func(s sigType) {
					s.(*HeadRequest).Address.CID[0]++
				},
				func(s sigType) {
					s.(*HeadRequest).Address.ObjectID[0]++
				},
				func(s sigType) {
					s.(*HeadRequest).FullHeaders = true
				},
			},
		},
		{ // DeleteRequest
			constructor: func() sigType {
				return new(DeleteRequest)
			},
			payloadCorrupt: []func(sigType){
				func(s sigType) {
					s.(*DeleteRequest).OwnerID[0]++
				},
				func(s sigType) {
					s.(*DeleteRequest).Address.CID[0]++
				},
				func(s sigType) {
					s.(*DeleteRequest).Address.ObjectID[0]++
				},
			},
		},
		{ // GetRangeRequest
			constructor: func() sigType {
				return new(GetRangeRequest)
			},
			payloadCorrupt: []func(sigType){
				func(s sigType) {
					s.(*GetRangeRequest).Range.Length++
				},
				func(s sigType) {
					s.(*GetRangeRequest).Range.Offset++
				},
				func(s sigType) {
					s.(*GetRangeRequest).Address.CID[0]++
				},
				func(s sigType) {
					s.(*GetRangeRequest).Address.ObjectID[0]++
				},
			},
		},
		{ // GetRangeHashRequest
			constructor: func() sigType {
				return &GetRangeHashRequest{
					Ranges: []Range{{}},
					Salt:   []byte{1, 2, 3},
				}
			},
			payloadCorrupt: []func(sigType){
				func(s sigType) {
					s.(*GetRangeHashRequest).Address.CID[0]++
				},
				func(s sigType) {
					s.(*GetRangeHashRequest).Address.ObjectID[0]++
				},
				func(s sigType) {
					s.(*GetRangeHashRequest).Salt[0]++
				},
				func(s sigType) {
					s.(*GetRangeHashRequest).Ranges[0].Length++
				},
				func(s sigType) {
					s.(*GetRangeHashRequest).Ranges[0].Offset++
				},
				func(s sigType) {
					s.(*GetRangeHashRequest).Ranges = nil
				},
			},
		},
		{ // GetRangeHashRequest
			constructor: func() sigType {
				return &SearchRequest{
					Query: []byte{1, 2, 3},
				}
			},
			payloadCorrupt: []func(sigType){
				func(s sigType) {
					s.(*SearchRequest).ContainerID[0]++
				},
				func(s sigType) {
					s.(*SearchRequest).Query[0]++
				},
				func(s sigType) {
					s.(*SearchRequest).QueryVersion++
				},
			},
		},
	}

	for _, item := range items {
		{ // token corruptions
			v := item.constructor()

			token := new(Token)
			v.SetToken(token)

			require.NoError(t, service.SignDataWithSessionToken(sk, v))

			require.NoError(t, service.VerifyAccumulatedSignaturesWithToken(v))

			token.SetSessionKey(append(token.GetSessionKey(), 1))

			require.Error(t, service.VerifyAccumulatedSignaturesWithToken(v))
		}

		{ // payload corruptions
			for _, corruption := range item.payloadCorrupt {
				v := item.constructor()

				require.NoError(t, service.SignDataWithSessionToken(sk, v))

				require.NoError(t, service.VerifyAccumulatedSignaturesWithToken(v))

				corruption(v)

				require.Error(t, service.VerifyAccumulatedSignaturesWithToken(v))
			}
		}
	}
}