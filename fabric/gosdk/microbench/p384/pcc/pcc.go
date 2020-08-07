//+build !s390x

package pcc

import (
	"errors"
)

// ScalarMultP384 calls the PCC instruction with the given params.
// See the Principles of Operation for more information on the
// parameters this function expects.
func ScalarMultP384(sourceX, sourceY, scalar [48]byte) (resultX, resultY [48]byte, err error) {
	// function stub for platforms that are not IBM Z
	return [48]byte{}, [48]byte{}, errors.New("function not supported on current platform")
}
