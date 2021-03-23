package signature

import (
	"crypto/ecdsa"

	crypto "github.com/nspcc-dev/neofs-crypto"
)

type cfg struct {
	signFunc   func(key *ecdsa.PrivateKey, msg []byte) ([]byte, error)
	verifyFunc func(key *ecdsa.PublicKey, msg []byte, sig []byte) error
	// unmarshalPublic is function used to unmarshal public key.
	unmarshalPublic func([]byte) *ecdsa.PublicKey
}

// defaultCfg represents default set of options.
func defaultCfg() *cfg {
	return &cfg{
		signFunc:        crypto.Sign,
		verifyFunc:      crypto.Verify,
		unmarshalPublic: crypto.UnmarshalPublicKey,
	}
}

func SignWithRFC6979() SignOption {
	return func(c *cfg) {
		c.signFunc = crypto.SignRFC6979
		c.verifyFunc = crypto.VerifyRFC6979
	}
}

// WithUnmarshalPublicKey sets f as a function for unmarshaling public keys.
func WithUnmarshalPublicKey(f func([]byte) *ecdsa.PublicKey) SignOption {
	return func(c *cfg) {
		c.unmarshalPublic = f
	}
}
