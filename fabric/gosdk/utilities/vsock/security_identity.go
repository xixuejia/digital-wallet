package vsock

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/gogo/protobuf/proto"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/core"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/msp"
	"github.com/mdlayher/vsock"
)

type worker struct {
	c *vsock.Conn
}
type workers struct {
	cid              int
	port             int
	availableWorkers chan *worker
}

type secureSigningIdentity struct {
	*secureIdentity
}

type secureIdentity struct {
	Mspid   string
	workers *workers
	pubKey  *ecdsa.PublicKey `json:"-"`
}

func NewSecureIdentity(cid, port, maxConnections int, mspID, pathToKeyAndCert string) (secureSigningId msp.SigningIdentity, err error) {
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
	return &secureSigningIdentity{
		&secureIdentity{
			pubKey:  ecdsaPubKey,
			Mspid:   mspID,
			workers: newWorkers(cid, port, maxConnections),
		},
	}, nil
}

func (ssi *secureSigningIdentity) Sign(msg []byte) ([]byte, error) {
	digest := sha256.Sum256(msg)
	return ssi.signDigest(digest[:])
}

func (ssi *secureSigningIdentity) signDigest(digest []byte) ([]byte, error) {
	return ssi.workers.sign(digest)
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
	return errors.New("Verify not implemented")
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
	return []byte{}
}

// SKI returns the subject key identifier of the key
func (si *secureIdentity) SKI() (ski []byte) {
	return []byte{}
}

// Bytes converts this key to its byte representation,
// if this operation is allowed.
func (si *secureIdentity) Bytes() (raw []byte, err error) {
	return []byte{}, errors.New("Bytes not implemented")
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

func (w *worker) sign(digest []byte) ([]byte, error) {
	n, err := w.c.Write(digest)
	if err != nil {
		return []byte{}, err
	} else if n != len(digest) {
		return []byte{}, fmt.Errorf("digest len: %d != n: %d", len(digest), n)
	}
	sig := make([]byte, 256)
	n, err = w.c.Read(sig)
	if err != nil {
		return []byte{}, err
	}
	return sig[:n], nil
}

func (w *worker) close() error {
	return w.c.Close()
}

func newWorker(cid, port int) (*worker, error) {
	c, err := vsock.Dial(uint32(cid), uint32(port))
	if err != nil {
		return nil, err
	}
	return &worker{c: c}, nil
}

func (ws *workers) sign(digest []byte) ([]byte, error) {
	var w *worker
	var err error
	select {
	case w = <-ws.availableWorkers:
		break
	default:
		w, err = newWorker(ws.cid, ws.port)
		if err != nil {
			return []byte{}, err
		}
	}
	sig, err := w.sign(digest)
	select { // give the worker back to the pool if there's room in the pool
	case ws.availableWorkers <- w:
	default:
		w.close() // there's no room in the pool, close the conneciton
	}
	return sig, err
}

func newWorkers(cid, port, maxConnections int) *workers {
	return &workers{
		cid:              cid,
		port:             port,
		availableWorkers: make(chan *worker, maxConnections),
	}
}
