#include "textflag.h"

// func pcc(function uint64, params *[4096]byte) (conditionCode uint64)
TEXT ·pcc(SB), NOSPLIT|NOFRAME, $0-24
MOVD function+0(FP), R0 // function code
MOVD params+8(FP), R1   // address of parameter block

loop:
WORD $0xB92C0000 // perform cryptographic computation
BRC  $1, loop    // branch back if interrupted
BRC  $2, cc2     // condition code of 2 indicates a failure
BRC  $4, cc1     // condition code of 1 indicates a failure

success:
MOVD $0, conditionCode+16(FP) // return 0 - scalar multiply was successful
RET

cc1:
MOVD $1, conditionCode+16(FP) // return 1
RET

cc2:
MOVD $2, conditionCode+16(FP) // return 2
RET
