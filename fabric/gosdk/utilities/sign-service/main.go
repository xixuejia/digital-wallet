package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"io"
	"io/ioutil"
	"log"
	"net"
	"strings"

	"github.com/hyperledger/fabric/bccsp/utils"
	"github.com/mdlayher/vsock"
)

func main() {

	var (
		flagPrivateKeyPath = flag.String("k", "", "the private key path")
		flagServer         = flag.Bool("s", false, "is it run as server")
		flagPort           = flag.Uint("p", 0, "port ID to listen on or connect to")
		flagContextID      = flag.Uint("c", 0, "the context ID of the server")
		flagDigest         = flag.String("d", "", "the digest to be signed")
	)
	flag.Parse()
	switch {
	case *flagContextID == 0 && !*flagServer:
		log.Fatalf(`specify either "-s" or "-c"`)
	case *flagContextID > 0:
		log.Printf("Connecting as client...")
		res, err := client(uint32(*flagContextID), uint32(*flagPort), *flagDigest)
		if err != nil {
			log.Fatalf("error connecting vsock server: %s", err)
		} else {
			log.Printf("result from server: %s", res)
		}
	case *flagServer:
		log.Printf("Run as server...")
		priv, err := loadECDSAPrivKey(*flagPrivateKeyPath)
		if err != nil {
			log.Fatalf("unable to load ecdsa private key: %s", err)
			return
		}
		for {
			if err := serve(uint32(*flagPort), priv); err != nil {
				log.Fatalf("error serving vsock: %s", err)
				return
			}
		}
	default:
		flag.PrintDefaults()
	}
}

func serve(port uint32, priv *ecdsa.PrivateKey) error {
	l, err := vsock.Listen(port)
	if err != nil {
		return err
	}
	defer l.Close()
	handler := func(c net.Conn) {
		defer c.Close()
		for {
			digest := make([]byte, 256)
			n, err := c.Read(digest)
			if err != nil {
				if err == io.EOF {
					log.Println("connection closed")
					return
				}
				log.Fatalf("reading data error: %s", err)
				return
			}
			sig, err := signWithECDSA(priv, digest[:n])
			if err != nil {
				log.Fatalf("sign error: %s", err)
				return
			}
			wn, err := c.Write(sig)
			if err != nil {
				log.Fatalf("write sig error: %s", err)
				return
			}
			if wn != len(sig) {
				log.Fatalf("sig len: %d != write len: %d", len(sig), wn)
				return
			}
		}
	}
	for {
		c, err := l.Accept()
		if err != nil {
			return err
		}
		go handler(c) // connection c will be closed in the handler after use
	}
}

func client(cid, port uint32, digest string) (string, error) {
	c, err := vsock.Dial(cid, port)
	if err != nil {
		return "", err
	}
	defer c.Close()
	digests := strings.Split(digest, ",") // sign multiple digests separted by comma
	res := ""
	for _, dig := range digests {
		_, err = c.Write([]byte(dig))
		if err != nil {
			break
		}
		signature := make([]byte, 1024)
		n, err := c.Read(signature)
		if err != nil {
			return "", err
		}
		res += dig + ":" + string(signature[:n]) + "\n"
	}
	return res, err
}

func loadECDSAPrivKey(keypath string) (*ecdsa.PrivateKey, error) {
	data, err := ioutil.ReadFile(keypath)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("unable to decode pem")
	}
	x509Encoded := block.Bytes
	ecdsaPemPrivKey, err := x509.ParsePKCS8PrivateKey(x509Encoded)
	if err != nil {
		return nil, err
	}
	ecdsaPrivateKey, ok := ecdsaPemPrivKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("unable to convert ecdsa private key")
	}
	return ecdsaPrivateKey, nil
}

func signWithECDSA(ecdsaPrivateKey *ecdsa.PrivateKey, digest []byte) ([]byte, error) {
	r, s, err := ecdsa.Sign(rand.Reader, ecdsaPrivateKey, digest[:])
	if err != nil {
		return []byte{}, err
	}
	s, _, err = utils.ToLowS(&ecdsaPrivateKey.PublicKey, s)
	if err != nil {
		return nil, err
	}
	return utils.MarshalECDSASignature(r, s)
}
