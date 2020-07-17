package utilities

import (
	"os"
	"testing"
)

func TestSecureSigningIdentity(t *testing.T) {
	signingID, err := NewSecureIdentity(os.ExpandEnv("$GOPATH/src/github.com/xixuejia/digital-wallet/fabric/gosdk/"+
		"fixtures/sdk-crypto/org1.example.com/users/Admin@org1.example.com/msp"), "org1", 1)
	if err != nil {
		t.Errorf("Error creating signing id: %s", err)
		t.FailNow()
	}
	msg := "hello world"
	signature, err := signingID.Sign([]byte(msg))
	if err != nil {
		t.Errorf("Error signing msg: %s", err)
		t.FailNow()
	}
	if err := signingID.Verify([]byte(msg), signature); err != nil {
		t.Errorf("Error verifying signature: %s", err)
		t.FailNow()
	}
}
