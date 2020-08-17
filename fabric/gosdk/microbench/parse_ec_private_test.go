package microbench

import (
	"encoding/hex"
	"testing"

	"github.com/xixuejia/digital-wallet/fabric/gosdk/microbench/p384"
)

// Generated using:
//   openssl ecparam -genkey -name secp256r1 | openssl pkcs8 -topk8 -nocrypt
var pkcs8P256PrivateKeyHex = `308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420dad6b2f49ca774c36d8ae9517e935226f667c929498f0343d2424d0b9b591b43a14403420004b9c9b90095476afe7b860d8bd43568cab7bcb2eed7b8bf2fa0ce1762dd20b04193f859d2d782b1e4cbfd48492f1f533113a6804903f292258513837f07fda735`

// Generated using:
//   openssl ecparam -genkey -name secp384r1 | openssl pkcs8 -topk8 -nocrypt
var pkcs8P384PrivateKeyHex = `3081b6020100301006072a8648ce3d020106052b8104002204819e30819b02010104309bf832f6aaaeacb78ce47ffb15e6fd0fd48683ae79df6eca39bfb8e33829ac94aa29d08911568684c2264a08a4ceb679a164036200049070ad4ed993c7770d700e9f6dc2baa83f63dd165b5507f98e8ff29b5d2e78ccbe05c8ddc955dbf0f7497e8222cfa49314fe4e269459f8e880147f70d785e530f2939e4bf9f838325bb1a80ad4cf59272ae0e5efe9a9dc33d874492596304bd3`

func BenchmarkParseECp256(b *testing.B) {
	derBytes, _ := hex.DecodeString(pkcs8P256PrivateKeyHex)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p384.ParsePKCS8PrivateKey(derBytes)
	}
}

func BenchmarkParseECp384(b *testing.B) {
	derBytes, _ := hex.DecodeString(pkcs8P384PrivateKeyHex)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p384.ParsePKCS8PrivateKey(derBytes)
	}
}

func TestParseECp384(t *testing.T) {
	derBytes, _ := hex.DecodeString(pkcs8P384PrivateKeyHex)
	if _, err := p384.ParsePKCS8PrivateKey(derBytes); err != nil {
		t.Errorf("Error parsing p384 key: %s", err)
		t.FailNow()
	}
}
