package utilities

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

// GenAESKey generate aes key from a user defined password
func GenAESKey(passwd string) [sha512.Size256]byte {
	return sha512.Sum512_256([]byte(passwd))
}

// GenAESKeyWithHash will generate AES key by numOfHash of sha512 hashes
func GenAESKeyWithHash(passwd string, numOfHash int) [sha512.Size256]byte {
	if numOfHash <= 1 {
		return GenAESKey(passwd)
	}
	var res512 [sha512.Size]byte
	passwdBytes := []byte(passwd)
	res512 = sha512.Sum512(passwdBytes)
	numOfHash--
	h := sha512.New()
	for numOfHash > 0 {
		h.Reset()
		h.Write(res512[:])
		h.Write(passwdBytes)
		copy(res512[:], h.Sum(nil))
		numOfHash--
	}
	var res256 [sha512.Size256]byte
	copy(res256[:], res512[:sha512.Size256])
	return res256
}

// Encrypt will encrypt plain text with aes 256 cbc mode
func Encrypt(key []byte, plain string) (cypherText string, err error) {
	plainText := []byte(plain)
	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}
	// add padding to plain text
	if plainText, err = pkcs7Padding(plainText, aes.BlockSize); err != nil {
		return
	}
	cipherText := make([]byte, aes.BlockSize+len(plainText))
	iv := cipherText[:aes.BlockSize]
	// generate random initialization vector
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return
	}
	cbcEncrypter := cipher.NewCBCEncrypter(block, iv)
	cbcEncrypter.CryptBlocks(cipherText[aes.BlockSize:], plainText)
	//returns base64 encoded string
	cypherText = base64.URLEncoding.EncodeToString(cipherText)
	return
}

// Decrypt will decrypt cipher text with aes 256 key
func Decrypt(key []byte, cipherText string) (plain string, err error) {
	cipherBytes, err := base64.URLEncoding.DecodeString(cipherText)
	if err != nil {
		return
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}
	if len(cipherBytes) < aes.BlockSize {
		err = errors.New("Ciphertext block size is too short")
		return
	}
	iv := cipherBytes[:aes.BlockSize]
	cbcDecrypter := cipher.NewCBCDecrypter(block, iv)
	plainBytes := make([]byte, len(cipherBytes)-aes.BlockSize)
	cbcDecrypter.CryptBlocks(plainBytes, cipherBytes[aes.BlockSize:])
	plainBytes, err = pkcs7Unpadding(plainBytes, aes.BlockSize)
	plain = string(plainBytes)
	return
}

// pkcs7Unpadding remove pkcs7 padding
func pkcs7Unpadding(data []byte, blockSize int) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, errors.New("pkcs7: Data is empty")
	}
	if length%blockSize != 0 {
		return nil, errors.New("pkcs7: Data is not block-aligned")
	}
	padLen := int(data[length-1])
	ref := bytes.Repeat([]byte{byte(padLen)}, padLen)
	if padLen > blockSize || padLen == 0 || !bytes.HasSuffix(data, ref) {
		return nil, errors.New("pkcs7: Invalid padding")
	}
	return data[:length-padLen], nil
}

// pkcs7Padding add pkcs7 padding
func pkcs7Padding(data []byte, blockSize int) ([]byte, error) {
	if blockSize <= 0 || blockSize > 256 {
		return nil, fmt.Errorf("pkcs7: Invalid block size %d", blockSize)
	}
	padLen := blockSize - len(data)%blockSize
	padding := bytes.Repeat([]byte{byte(padLen)}, padLen)
	return append(data, padding...), nil
}
