package signature

import (
	"crypto/ecdsa"
	"fmt"

	lru "github.com/hashicorp/golang-lru"
	"github.com/nspcc-dev/neofs-api-go/v2/refs"
	crypto "github.com/nspcc-dev/neofs-crypto"
)

type cfg struct {
	schemeFixed bool
	scheme      refs.SignatureScheme
	buffer      []byte
}

func defaultCfg() *cfg {
	return new(cfg)
}

// keycache is a simple lru cache for P256 keys that avoids Y calculation overhead
// for known keys.
var keycache *lru.Cache

func init() {
	// Less than 100K, probably enough for our purposes.
	keycache, _ = lru.New(1024)
}

func verify(cfg *cfg, data []byte, sig *refs.Signature) error {
	if !cfg.schemeFixed {
		cfg.scheme = sig.GetScheme()
	}

	var pub *ecdsa.PublicKey
	k := string(sig.GetKey())
	cachedKey, ok := keycache.Get(k)
	if ok {
		pub = cachedKey.(*ecdsa.PublicKey)
	} else {
		pub = crypto.UnmarshalPublicKey(sig.GetKey())
		keycache.Add(k, pub)
	}

	switch cfg.scheme {
	case refs.ECDSA_SHA512:
		return crypto.Verify(pub, data, sig.GetSign())
	case refs.ECDSA_RFC6979_SHA256:
		return crypto.VerifyRFC6979(pub, data, sig.GetSign())
	default:
		return fmt.Errorf("unsupported signature scheme %s", cfg.scheme)
	}
}

func sign(cfg *cfg, key *ecdsa.PrivateKey, data []byte) ([]byte, error) {
	switch cfg.scheme {
	case refs.ECDSA_SHA512:
		return crypto.Sign(key, data)
	case refs.ECDSA_RFC6979_SHA256:
		return crypto.SignRFC6979(key, data)
	default:
		panic(fmt.Sprintf("unsupported scheme %s", cfg.scheme))
	}
}

func SignWithRFC6979() SignOption {
	return func(c *cfg) {
		c.schemeFixed = true
		c.scheme = refs.ECDSA_RFC6979_SHA256
	}
}

// WithBuffer allows providing pre-allocated buffer for signature verification.
func WithBuffer(buf []byte) SignOption {
	return func(c *cfg) {
		c.buffer = buf
	}
}
