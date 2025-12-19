package speck

import (
	"encoding/binary"
	"math/bits"
)

func ExpandKey(k []uint64, K []byte) {
	l := make([]uint64, 32)

	l[0] = binary.LittleEndian.Uint64(K[8:])
	k[0] = binary.LittleEndian.Uint64(K[0:])

	for i := uint64(0); i < 32-1; i++ {
		l[i+1] = (k[i] + bits.RotateLeft64(l[i], -8)) ^ i
		k[i+1] = bits.RotateLeft64(k[i], 3) ^ l[i+1]
	}
}
