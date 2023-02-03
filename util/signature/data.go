package signature

import (
	"crypto/ecdsa"

	"github.com/TrueCloudLab/frostfs-api-go/v2/refs"
)

type KeySignatureHandler func(*refs.Signature)

type KeySignatureSource func() *refs.Signature

func SignDataWithHandler(key *ecdsa.PrivateKey, src DataSource, handler KeySignatureHandler, opts ...SignOption) error {
	s, err := NewSigner(key, nil)
	if err != nil {
		return err
	}

	sig, err := s.Sign(src, opts...)
	if err != nil {
		return err
	}

	handler(sig)
	return nil
}

func VerifyDataWithSource(src DataSource, sigSrc KeySignatureSource, opts ...SignOption) error {
	s := NewVerifier(nil)
	return s.Verify(src, sigSrc(), opts...)
}

func SignData(key *ecdsa.PrivateKey, v DataWithSignature, opts ...SignOption) error {
	return SignDataWithHandler(key, v, v.SetSignature, opts...)
}

func VerifyData(src DataWithSignature, opts ...SignOption) error {
	return VerifyDataWithSource(src, src.GetSignature, opts...)
}
