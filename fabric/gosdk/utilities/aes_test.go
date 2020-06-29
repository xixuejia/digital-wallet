package utilities

import (
	"fmt"
	"testing"
)

func TestAES(t *testing.T) {
	password := "passw0rd"
	plainText := "hello world"
	var key [32]byte
	for _, key = range [][32]byte{GenAESKey(password), GenAESKeyWithHash(password, 10)} {
		cipherText, err := Encrypt(key[:], plainText)
		if err != nil {
			t.Errorf("Error in aes-256-cbc encryption: %s", err)
			t.FailNow()
		}
		fmt.Printf("cipher text: %s\n", cipherText)
		decryptedMsg, err := Decrypt(key[:], cipherText)
		if err != nil {
			t.Errorf("Error in aes-256-cbc encryption: %s", err)
			t.FailNow()
		}
		if decryptedMsg != plainText {
			t.Errorf("Original message: %s, decrypted message: %s", plainText, decryptedMsg)
			t.FailNow()
		}
	}
}
