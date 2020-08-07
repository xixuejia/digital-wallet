package pcc

import (
	"errors"
)

// ScalarMultP384 calls the PCC instruction with the given params.
// See the Principles of Operation for more information on the
// parameters this function expects.
func ScalarMultP384(sourceX, sourceY, scalar [48]byte) (resultX, resultY [48]byte, err error) {
	params := [4096]byte{}
	copy(params[0x60:0x90], sourceX[:])
	copy(params[0x90:0xc0], sourceY[:])
	copy(params[0xc0:0xf0], scalar[:])
	switch pcc(65, &params) {
	case 0:
		// success
		copy(resultX[:], params[0x00:0x30])
		copy(resultY[:], params[0x30:0x60])
		return resultX, resultY, nil
	case 1:
		return [48]byte{}, [48]byte{}, errors.New("condition code 1")
	case 2:
		return [48]byte{}, [48]byte{}, errors.New("condition code 2")
	}
	// should not happen... condition code 3 is handled in assembly
	return [48]byte{}, [48]byte{}, errors.New("unexpected condition code")
}

//go:noescape
func pcc(function uint64, params *[4096]byte) uint64
