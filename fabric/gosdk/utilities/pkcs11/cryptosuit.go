package pkcs11

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"

	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/core"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/fab"
	"github.com/hyperledger/fabric-sdk-go/pkg/fab/signingmgr"
	"github.com/hyperledger/fabric-sdk-go/pkg/fabsdk/provider/fabpvdr"
	"github.com/hyperledger/fabric/bccsp/utils"
)

type cryptoSuite struct {
	keys map[string]core.Key
}

func (c cryptoSuite) KeyGen(opts core.KeyGenOpts) (k core.Key, err error) {
	return nil, errors.New("func KeyGen is not supported")
}

func (c cryptoSuite) KeyImport(raw interface{}, opts core.KeyImportOpts) (k core.Key, err error) {
	switch raw.(type) {
	case *x509.Certificate:
		cert := raw.(*x509.Certificate)
		pubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return nil, errors.New("invalid key type, it must be ECDSA Public Key")
		}
		si := &secureIdentity{pubKey: pubKey}
		if _, ok := c.keys[hex.EncodeToString(si.SKI())]; !ok {
			c.keys[hex.EncodeToString(si.SKI())] = si
		}
		return si, nil
	case *ecdsa.PublicKey:
		si := &secureIdentity{pubKey: raw.(*ecdsa.PublicKey)}
		c.keys[hex.EncodeToString(si.SKI())] = si
		return si, nil
	default:
		return nil, errors.New("unknown key type to import")
	}
}

func (c cryptoSuite) GetKey(ski []byte) (k core.Key, err error) {
	key, ok := c.keys[hex.EncodeToString(ski)]
	if !ok {
		return nil, fmt.Errorf("key with ski %s is not found", hex.EncodeToString(ski))
	}
	return key, nil
}

func (c cryptoSuite) Hash(msg []byte, opts core.HashOpts) (hash []byte, err error) {
	h, err := c.GetHash(opts)
	if err != nil {
		return nil, err
	}
	h.Reset()
	h.Write(msg)
	defer h.Reset()
	return h.Sum(nil), nil
}

func (c cryptoSuite) GetHash(opts core.HashOpts) (h hash.Hash, err error) {
	return sha256.New(), nil
}

func (c cryptoSuite) Sign(k core.Key, digest []byte, opts core.SignerOpts) (signature []byte, err error) {
	switch k.(type) {
	case *secureSigningIdentity:
		ssi := k.(*secureSigningIdentity)
		return ssi.signDigest(digest)
	default:
		return nil, fmt.Errorf("unsupported key type %T for Sign", k)
	}
}

func (c cryptoSuite) Verify(k core.Key, signature, digest []byte, opts core.SignerOpts) (valid bool, err error) {
	switch k.(type) {
	case *secureIdentity:
		si := k.(*secureIdentity)
		r, s, err := utils.UnmarshalECDSASignature(signature)
		if err != nil {
			return false, fmt.Errorf("unable to unmarshal signature: %s", err)
		}
		return ecdsa.Verify(si.pubKey, digest, r, s), nil
	default:
		return false, fmt.Errorf("unsupported key type %T for Verify", k)
	}
}

type ProviderFactory struct{}

func (p ProviderFactory) CreateCryptoSuiteProvider(config core.CryptoSuiteConfig) (core.CryptoSuite, error) {
	return &cryptoSuite{keys: make(map[string]core.Key)}, nil
}

func (p ProviderFactory) CreateSigningManager(cryptoProvider core.CryptoSuite) (core.SigningManager, error) {
	return signingmgr.New(cryptoProvider)
}

func (p ProviderFactory) CreateInfraProvider(config fab.EndpointConfig) (fab.InfraProvider, error) {
	return fabpvdr.New(config), nil
}

func NewProviderFactory() *ProviderFactory {
	return &ProviderFactory{}
}
