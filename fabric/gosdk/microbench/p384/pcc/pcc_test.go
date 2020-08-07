// +build s390x

package pcc

import (
	"testing"
)

func TestScalarMultP384(t *testing.T) {
	// TODO: turn this into a real test
	rx, ry, err := ScalarMultP384([48]byte{}, [48]byte{}, [48]byte{})
	if err != nil {
		t.Logf("error: %v", err)
	}
	_, _ = rx, ry
}
