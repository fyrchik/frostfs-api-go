package signature

import "github.com/TrueCloudLab/frostfs-api-go/v2/refs"

// Verifier allows to verify multiple signatures in batch.
type Verifier struct {
	buffer []byte
}

// NewVerifier returns new Verifier.
func NewVerifier(buffer []byte) *Verifier {
	return &Verifier{buffer: buffer}
}

// Verify checks if sig is a correct signature for src.
func (s *Verifier) Verify(src DataSource, sig *refs.Signature, opts ...SignOption) error {
	s.buffer = getBuffer(s.buffer, src.SignedDataSize())

	data, err := src.ReadSignedData(s.buffer)
	if err != nil {
		return err
	}

	return verify(data, sig, opts...)
}

// VerifyStable checks if sig is a correct signature for src.
// It is similar to Verify but accepts another interface.
func (s *Verifier) VerifyStable(src StableMarshaler, sig *refs.Signature, opts ...SignOption) error {
	s.buffer = getBuffer(s.buffer, src.StableSize())

	data := src.StableMarshal(s.buffer)
	return verify(data, sig, opts...)
}
