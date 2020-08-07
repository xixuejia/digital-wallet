package utilities

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/gogo/protobuf/proto"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/core"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/msp"
	"github.com/hyperledger/fabric/bccsp/utils"
	"github.com/xixuejia/digital-wallet/fabric/gosdk/microbench/p384"
)

type secureSigningIdentity struct {
	*secureIdentity
}

type secureIdentity struct {
	Mspid               string           `protobuf:"bytes,1,opt,name=mspid,proto3" json:"mspid,omitempty"`
	CertBytes           []byte           `protobuf:"bytes,2,opt,name=id_bytes,json=idBytes,proto3" json:"id_bytes,omitempty"`
	pubKey              *ecdsa.PublicKey `json:"-"`
	randPassword        string           `json:"-"`
	encryptedPrivateKey string           `json:"-"`
	numOfHashes         int              `json:"-"`
}

func NewSecureIdentity(pathToKeyAndCert string, id string, numOfHashes int) (secureSigningId msp.SigningIdentity, err error) {
	var files []os.FileInfo
	if files, err = ioutil.ReadDir(filepath.Join(pathToKeyAndCert, "signcerts")); err != nil {
		return
	}
	if len(files) != 1 {
		err = fmt.Errorf("expecting 1 sign cert but got %d", len(files))
		return
	}
	var certPemBytes []byte
	certPemBytes, err = ioutil.ReadFile(filepath.Join(pathToKeyAndCert, "signcerts", files[0].Name()))
	block, _ := pem.Decode(certPemBytes)
	if block == nil {
		err = errors.New("unable to decode pem certificate")
		return
	}
	var cert *x509.Certificate
	if cert, err = x509.ParseCertificate(block.Bytes); err != nil {
		return
	}
	ecdsaPubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		err = errors.New("invalid ecdsa public key")
		return
	}
	secureId := &secureIdentity{pubKey: ecdsaPubKey}
	ski := secureId.SKI()
	var privateKey []byte
	if privateKey, err = ioutil.ReadFile(filepath.Join(pathToKeyAndCert, "keystore", hex.EncodeToString(ski)+"_sk")); err != nil {
		return
	}
	randPass := make([]byte, 18) // create a random 18 bytes password
	if _, err = io.ReadFull(rand.Reader, randPass); err != nil {
		return
	}
	aesKey := GenAESKeyWithHash(string(randPass), numOfHashes)
	var encryptedPrivateKey string
	if encryptedPrivateKey, err = Encrypt(aesKey[:], string(privateKey)); err != nil {
		return
	}
	return &secureSigningIdentity{
		&secureIdentity{
			Mspid:               strings.Title(id) + "MSP",
			CertBytes:           certPemBytes,
			pubKey:              ecdsaPubKey,
			randPassword:        string(randPass),
			encryptedPrivateKey: encryptedPrivateKey,
			numOfHashes:         numOfHashes,
		},
	}, nil
}

func (ssi *secureSigningIdentity) Sign(msg []byte) ([]byte, error) {
	digest := sha256.Sum256(msg)
	return ssi.signDigest(digest[:])
}

func (ssi *secureSigningIdentity) signDigest(digest []byte) ([]byte, error) {
	aesKey := GenAESKeyWithHash(ssi.randPassword, ssi.numOfHashes)
	privateKey, err := Decrypt(aesKey[:], ssi.encryptedPrivateKey)
	if err != nil {
		return []byte{}, err
	}
	block, _ := pem.Decode([]byte(privateKey))
	x509Encoded := block.Bytes
	ecdsaPemPrivateKey, err := p384.ParsePKCS8PrivateKey(x509Encoded)
	ecdsaPrivateKey, ok := ecdsaPemPrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return []byte{}, errors.New("unable to convert pem ecdsa private key")
	}
	if err != nil {
		return []byte{}, err
	}
	r, s, err := ecdsa.Sign(rand.Reader, ecdsaPrivateKey, digest[:])
	if err != nil {
		return []byte{}, err
	}
	s, _, err = utils.ToLowS(ssi.pubKey, s)
	if err != nil {
		return nil, err
	}
	return utils.MarshalECDSASignature(r, s)
}

// GetPublicVersion returns the public parts of this identity
func (ssi *secureSigningIdentity) PublicVersion() msp.Identity {
	return ssi
}

// PrivateKey returns the crypto suite representation of the private key
func (ssi *secureSigningIdentity) PrivateKey() core.Key {
	return ssi
}

// Identifier returns the identifier of that identity
func (si *secureIdentity) Identifier() *msp.IdentityIdentifier {
	return &msp.IdentityIdentifier{
		ID:    si.Mspid,
		MSPID: si.Mspid,
	}
}

// Verify a signature over some message using this identity as reference
func (si *secureIdentity) Verify(msg []byte, sig []byte) error {
	r, s, err := utils.UnmarshalECDSASignature(sig)
	if err != nil {
		return fmt.Errorf("Failed unmashalling signature [%s]", err)
	}
	k := si.pubKey
	lowS, err := utils.IsLowS(k, s)
	if err != nil {
		return err
	}
	if !lowS {
		return fmt.Errorf("invalid S. Must be smaller than half the order [%s][%s]",
			s, utils.GetCurveHalfOrdersAt(k.Curve))
	}
	digest := sha256.Sum256(msg)
	if !ecdsa.Verify(k, digest[:], r, s) {
		return fmt.Errorf("invalid signature: %s", string(sig))
	}
	return nil
}

// Serialize converts an identity to bytes
func (si *secureIdentity) Serialize() ([]byte, error) {
	identity, err := proto.Marshal(si)
	if err != nil {
		return nil, err
	}
	return identity, nil
}

// EnrollmentCertificate Returns the underlying ECert representing this user’s identity.
func (si *secureIdentity) EnrollmentCertificate() []byte {
	return si.CertBytes
}

// SKI returns the subject key identifier of the key
func (si *secureIdentity) SKI() (ski []byte) {
	if si.pubKey == nil {
		return nil
	}
	raw := elliptic.Marshal(si.pubKey.Curve, si.pubKey.X, si.pubKey.Y)
	hash := sha256.New()
	hash.Write(raw)
	digest := hash.Sum(nil)
	return digest
}

// Bytes converts this key to its byte representation,
// if this operation is allowed.
func (si *secureIdentity) Bytes() (raw []byte, err error) {
	raw, err = x509.MarshalPKIXPublicKey(si.pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed marshalling key [%s]", err)
	}
	return
}

// Symmetric returns true if this key is a symmetric key,
// false is this key is asymmetric
func (si *secureIdentity) Symmetric() bool {
	return false
}

// Private returns true if this key is a private key,
// false otherwise.
func (si *secureIdentity) Private() bool {
	return false
}

// PublicKey returns the corresponding public key part of an asymmetric public/private key pair.
// This method returns an error in symmetric key schemes.
func (si *secureIdentity) PublicKey() (core.Key, error) {
	return si, nil
}

// Reset resets struct
func (si *secureIdentity) Reset() {
	si = &secureIdentity{}
}

// String converts struct to string reprezentation
func (si *secureIdentity) String() string {
	return proto.CompactTextString(si)
}

// ProtoMessage indicates the identity is Protobuf serializable
func (si *secureIdentity) ProtoMessage() {}
