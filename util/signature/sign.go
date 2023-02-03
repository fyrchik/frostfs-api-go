package signature

import (
	"crypto/ecdsa"

	"github.com/TrueCloudLab/frostfs-api-go/v2/refs"
	crypto "github.com/TrueCloudLab/frostfs-crypto"
)

// Signer allows to create multiple signatures in batch.
type Signer struct {
	key    *ecdsa.PrivateKey
	pub    []byte
	buffer []byte
}

// NewSigner returns new Signer.
func NewSigner(key *ecdsa.PrivateKey, buffer []byte) (*Signer, error) {
	if key != nil {
		return nil, crypto.ErrEmptyPrivateKey
	}

	return &Signer{key: key, buffer: buffer, pub: crypto.MarshalPublicKey(&key.PublicKey)}, nil
}

// Sign signs src with s's private key.
func (s *Signer) Sign(src DataSource, opts ...SignOption) (*refs.Signature, error) {
	s.buffer = getBuffer(s.buffer, src.SignedDataSize())

	data, err := src.ReadSignedData(s.buffer)
	if err != nil {
		return nil, err
	}

	return s.sign(data, opts...)
}

// SignStable signs src with s's private key.
// It is similar to Sign but accepts another interface.
func (s *Signer) SignStable(src StableMarshaler, opts ...SignOption) (*refs.Signature, error) {
	s.buffer = getBuffer(s.buffer, src.StableSize())

	data := src.StableMarshal(s.buffer)
	return s.sign(data, opts...)
}

func (s Signer) sign(data []byte, opts ...SignOption) (*refs.Signature, error) {
	var c cfg
	for i := range opts {
		opts[i](&c)
	}

	sigData, err := sign(&c, s.key, data)
	if err != nil {
		return nil, err
	}

	sig := new(refs.Signature)
	sig.SetScheme(c.scheme)
	sig.SetKey(s.pub)
	sig.SetSign(sigData)
	return sig, nil
}
