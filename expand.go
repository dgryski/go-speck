package speck

import "math/bits"

func ExpandKey(k, K []uint64) {
	l := make([]uint64, 32)

	l[0] = K[1]
	k[0] = K[0]

	for i := uint64(0); i < 32-1; i++ {
		l[i+1] = (k[i] + bits.RotateLeft64(l[i], -8)) ^ i
		k[i+1] = bits.RotateLeft64(k[i], 3) ^ l[i+1]
	}
}
