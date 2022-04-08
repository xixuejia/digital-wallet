package hpcs

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/gogo/protobuf/proto"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/core"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/msp"
	"github.com/hyperledger/fabric/bccsp/utils"
	"github.com/ibm-developer/ibm-cloud-hyperprotectcrypto/golang/ep11"
	pb "github.com/ibm-developer/ibm-cloud-hyperprotectcrypto/golang/grpc"
	"github.com/ibm-developer/ibm-cloud-hyperprotectcrypto/golang/util"
	uuid "github.com/satori/go.uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type secureSigningIdentity struct {
	*secureIdentity
}

type secureIdentity struct {
	Mspid             string `protobuf:"bytes,1,opt,name=mspid,proto3" json:"mspid,omitempty"`
	CertBytes         []byte `protobuf:"bytes,2,opt,name=id_bytes,json=idBytes,proto3" json:"id_bytes,omitempty"`
	pubKey            *ecdsa.PublicKey
	addr              string
	apiKey            string
	endpoint          string
	instanceID        string
	ep11key           []byte
	iv                []byte
	cryptoClient      pb.CryptoClient
	encryptedKeyBytes []byte
	clearKey          *ecdsa.PrivateKey
	sync.RWMutex
}

// NewSecureIdentity creates an identity instance to do signing operation
func NewSecureIdentity(pathToKeyAndCert, mspID, addr, apiKey, endpoint, instanceID string, unwrapInterval int) (
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
	if files, err = ioutil.ReadDir(filepath.Join(pathToKeyAndCert, "keystore")); err != nil {
		return
	}
	if len(files) != 1 {
		err = fmt.Errorf("expecting 1 private key file bug got %d", len(files))
		return
	}
	keyBytes, err := ioutil.ReadFile(filepath.Join(pathToKeyAndCert, "keystore", files[0].Name()))
	if err != nil {
		return
	}
	ep11key, iv, cryptoClient, err := genAESKeyAndIV(addr, apiKey, endpoint, instanceID)
	if err != nil {
		return
	}
	si := &secureIdentity{
		Mspid:        mspID,
		CertBytes:    certPemBytes,
		pubKey:       ecdsaPubKey,
		addr:         addr,
		apiKey:       apiKey,
		endpoint:     endpoint,
		instanceID:   instanceID,
		ep11key:      ep11key,
		iv:           iv,
		cryptoClient: cryptoClient,
	}
	ssi := &secureSigningIdentity{si}
	encryptedKeyBytes, err := ssi.encrypt(keyBytes)
	if err != nil {
		return
	}
	log.Printf("EC private key is encrypted!")
	ssi.encryptedKeyBytes = encryptedKeyBytes
	ssi.refreshKey() // initial unwrap EC private key with HPCS
	ticker := time.NewTicker(time.Second * time.Duration(unwrapInterval))
	go func() { // start a timer to periodically refresh the clear private key
		for {
			<-ticker.C
			ssi.refreshKey()
		}
	}()
	return ssi, nil
}

func (ssi *secureSigningIdentity) Sign(msg []byte) ([]byte, error) {
	digest := sha256.Sum256(msg)
	return ssi.signDigest(digest[:])
}

func (ssi *secureSigningIdentity) signDigest(digest []byte) ([]byte, error) {
	ssi.RLock()
	defer ssi.RUnlock()
	r, s, err := ecdsa.Sign(rand.Reader, ssi.clearKey, digest[:])
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

func (si *secureIdentity) encrypt(data []byte) ([]byte, error) {
	encipherSingleInfo := &pb.EncryptSingleRequest{
		Mech:  &pb.Mechanism{Mechanism: ep11.CKM_AES_CBC_PAD, Parameter: si.iv},
		Key:   si.ep11key,
		Plain: data,
	}
	encipher, err := si.cryptoClient.EncryptSingle(context.Background(), encipherSingleInfo)
	return encipher.Ciphered, err
}

func (si *secureIdentity) decrypt(ciphered []byte) ([]byte, error) {
	decipherSingleInfo := &pb.DecryptSingleRequest{
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_AES_CBC_PAD, Parameter: si.iv},
		Key:      si.ep11key,
		Ciphered: ciphered,
	}
	decipher, err := si.cryptoClient.DecryptSingle(context.Background(), decipherSingleInfo)
	return decipher.Plain, err
}

// refresh the clear private key
func (si *secureIdentity) refreshKey() {
	decryptedECKey, err := si.decrypt(si.encryptedKeyBytes)
	if err != nil {
		log.Fatalf("unable to decrypt ec key: %s", err)
	}
	block, _ := pem.Decode([]byte(decryptedECKey))
	x509Encoded := block.Bytes
	ecdsaPemPrivateKey, err := x509.ParsePKCS8PrivateKey(x509Encoded)
	if err != nil {
		log.Fatalf("unable to parse EC private key: %s", err.Error())
	}
	ecdsaPrivateKey, ok := ecdsaPemPrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		log.Fatal("unable to convert pem ecdsa private key")
	}
	log.Println("refreshing clear EC private key with HPCS")
	si.Lock()
	defer si.Unlock()
	si.clearKey = ecdsaPrivateKey
}

func genAESKeyAndIV(addr, apiKey, endpoint, instance string) ([]byte, []byte, pb.CryptoClient, error) {
	callOpts := []grpc.DialOption{
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{})),
		grpc.WithPerRPCCredentials(&util.IAMPerRPCCredentials{
			APIKey:   apiKey,
			Endpoint: endpoint,
			Instance: instance,
		}),
	}
	conn, err := grpc.Dial(addr, callOpts...)
	if err != nil {
		return []byte{}, []byte{}, nil, fmt.Errorf("unable to dial hpcs instance: %s", err)
	}
	// defer conn.Close()
	cryptoClient := pb.NewCryptoClient(conn)
	keyLen := 256
	keyTemplate := util.NewAttributeMap(
		util.NewAttribute(ep11.CKA_VALUE_LEN, (uint64)(keyLen/8)),
		util.NewAttribute(ep11.CKA_WRAP, false),
		util.NewAttribute(ep11.CKA_UNWRAP, false),
		util.NewAttribute(ep11.CKA_ENCRYPT, true),
		util.NewAttribute(ep11.CKA_DECRYPT, true),
		util.NewAttribute(ep11.CKA_EXTRACTABLE, false), // set to false!
		util.NewAttribute(ep11.CKA_TOKEN, true),        // ignored by EP11
	)

	keygenmsg := &pb.GenerateKeyRequest{
		Mech:     &pb.Mechanism{Mechanism: ep11.CKM_AES_KEY_GEN},
		Template: keyTemplate,
		KeyId:    uuid.NewV4().String(), // optional
	}
	generateKeyStatus, err := cryptoClient.GenerateKey(context.Background(), keygenmsg)
	if err != nil {
		return []byte{}, []byte{}, nil, fmt.Errorf("GenerateKey Error: %s", err)
	}
	rngTemplate := &pb.GenerateRandomRequest{
		Len: (uint64)(ep11.AES_BLOCK_SIZE),
	}
	rng, err := cryptoClient.GenerateRandom(context.Background(), rngTemplate)
	if err != nil {
		return []byte{}, []byte{}, nil, fmt.Errorf("GenerateRandom Error: %s", err)
	}
	iv := rng.Rnd[:ep11.AES_BLOCK_SIZE]
	return generateKeyStatus.Key, iv, cryptoClient, nil
}
