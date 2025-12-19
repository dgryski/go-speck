//go:build purego || !amd64

package speck

import "math/bits"

func ExpandKeyAndEncrypt(pt, ct, K []uint64) {

	B := K[1]
	A := K[0]

	ct0 := pt[0]
	ct1 := pt[1]
	for i := uint64(0); i < 32; i++ {
		// encryption
		ct1 = bits.RotateLeft64(ct1, -8)
		ct1 += ct0
		ct1 ^= A
		ct0 = bits.RotateLeft64(ct0, 3)
		ct0 ^= ct1

		// inline key expansion phase
		B = bits.RotateLeft64(B, -8)
		B += A
		B ^= i
		A = bits.RotateLeft64(A, 3)
		A ^= B
	}

	ct[0] = ct0
	ct[1] = ct1
}

func Encrypt(pt, ct, k []uint64) {
	ct1 := pt[1]
	ct0 := pt[0]

	for i := 0; i < 32; i++ {
		// encryption
		ct1 = bits.RotateLeft64(ct1, -8)
		ct1 += ct0
		ct1 ^= k[i]
		ct0 = bits.RotateLeft64(ct0, 3)
		ct0 ^= ct1
	}

	ct[0] = ct0
	ct[1] = ct1
}

func Decrypt(pt, ct, k []uint64) {
	ct0 := ct[0]
	ct1 := ct[1]

	for i := 31; i >= 0; i-- {
		// decryption
		ct0 ^= ct1
		ct0 = bits.RotateLeft64(ct0, -3)
		ct1 ^= k[i]
		ct1 -= ct0
		ct1 = bits.RotateLeft64(ct1, 8)
	}

	pt[0] = ct0
	pt[1] = ct1
}
