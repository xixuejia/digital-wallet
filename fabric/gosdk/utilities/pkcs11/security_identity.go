package pkcs11

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"

	"github.com/gogo/protobuf/proto"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/core"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/msp"
	"github.com/hyperledger/fabric/bccsp/utils"
	"github.com/miekg/pkcs11"
)

type secureSigningIdentity struct {
	*secureIdentity
}

type secureIdentity struct {
	Mspid     string `protobuf:"bytes,1,opt,name=mspid,proto3" json:"mspid,omitempty"`
	CertBytes []byte `protobuf:"bytes,2,opt,name=id_bytes,json=idBytes,proto3" json:"id_bytes,omitempty"`
	pubKey    *ecdsa.PublicKey
	ctx       *pkcs11.Ctx
	session   pkcs11.SessionHandle
	signKey   pkcs11.ObjectHandle
	slot      uint
}

// NewSecureIdentity creates an identity instance to do signing operation with PKCS11 interface
// pathToLib: the path to PKCS11 library file, e.g. /usr/local/lib/softhsm/libsofthsm2.so
// PIN: the user PIN
func NewSecureIdentity(pathToKeyAndCert, mspID, pathToLib, PIN, label string) (
	secureSigningID msp.SigningIdentity, err error) {
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
	if err != nil {
		return
	}
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
	si := &secureIdentity{
		Mspid:  mspID,
		pubKey: ecdsaPubKey,
	}
	p := pkcs11.New(pathToLib)
	if p == nil {
		err = fmt.Errorf("unable to new pkcs11 object with lib: %s", pathToLib)
		return
	}
	if err = p.Initialize(); err != nil {
		err = fmt.Errorf("unable to initialize pkcs11 library: %s", err.Error())
		return
	}
	si.ctx = p
	slots, err := p.GetSlotList(true)
	if err != nil {
		return
	}
	for _, s := range slots {
		info, err := p.GetTokenInfo(s)
		if err != nil || label != info.Label {
			continue
		}
		si.slot = s
	}
	sess, err := si.ctx.OpenSession(si.slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		err = fmt.Errorf("unable to open session: %s", err.Error())
		return
	}
	if err = si.ctx.Login(sess, pkcs11.CKU_USER, PIN); err != nil && err != pkcs11.Error(pkcs11.CKR_USER_ALREADY_LOGGED_IN) {
		err = fmt.Errorf("unable to login: %s", err.Error())
		return
	}
	si.session = sess
	// find sign key via ski
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_ID, si.SKI()),
	}
	if err = si.ctx.FindObjectsInit(si.session, template); err != nil {
		err = fmt.Errorf("unable to find object init: %s", err.Error())
		return
	}
	defer si.ctx.FindObjectsFinal(si.session)
	objs, _, err := si.ctx.FindObjects(si.session, 1)
	if err != nil {
		err = fmt.Errorf("unable to find object: %s", err.Error())
		return
	}

	if len(objs) == 0 {
		err = fmt.Errorf("key not found [%s]", hex.Dump(si.SKI()))
		return
	}
	si.signKey = objs[0]
	ssi := &secureSigningIdentity{si}
	return ssi, nil
}

func (ssi *secureSigningIdentity) Sign(msg []byte) ([]byte, error) {
	digest := sha256.Sum256(msg)
	return ssi.signDigest(digest[:])
}

func (ssi *secureSigningIdentity) signDigest(digest []byte) ([]byte, error) {
	err := ssi.ctx.SignInit(ssi.session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)}, ssi.signKey)
	if err != nil {
		return nil, fmt.Errorf("unable to do sign init: %s", err.Error())
	}
	var sig []byte
	sig, err = ssi.ctx.Sign(ssi.session, digest)
	if err != nil {
		return nil, fmt.Errorf("unable to do sign: %s", err.Error())
	}
	r := new(big.Int)
	s := new(big.Int)
	r.SetBytes(sig[0 : len(sig)/2])
	s.SetBytes(sig[len(sig)/2:])
	s, _, err = utils.ToLowS(ssi.pubKey, s)
	if err != nil {
		return nil, fmt.Errorf("unable to call ToLowS: %s", err.Error())
	}
	return utils.MarshalECDSASignature(r, s)
	// return []byte{}, errors.New("not implemented yet")
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
		return fmt.Errorf("failed unmashalling signature [%s]", err)
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
