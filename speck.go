//go:build purego || !amd64

package speck

import (
	"encoding/binary"
	"math/bits"
)

func ExpandKeyAndEncrypt(pt, ct, K []byte) {

	B := binary.LittleEndian.Uint64(K[8:])
	A := binary.LittleEndian.Uint64(K[0:])

	ct0 := binary.LittleEndian.Uint64(pt[0:])
	ct1 := binary.LittleEndian.Uint64(pt[8:])
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

	binary.LittleEndian.PutUint64(ct[0:], ct0)
	binary.LittleEndian.PutUint64(ct[8:], ct1)
}

func Encrypt(pt, ct []byte, k []uint64) {
	ct0 := binary.LittleEndian.Uint64(pt[0:])
	ct1 := binary.LittleEndian.Uint64(pt[8:])

	for i := 0; i < 32; i++ {
		// encryption
		ct1 = bits.RotateLeft64(ct1, -8)
		ct1 += ct0
		ct1 ^= k[i]
		ct0 = bits.RotateLeft64(ct0, 3)
		ct0 ^= ct1
	}

	binary.LittleEndian.PutUint64(ct[0:], ct0)
	binary.LittleEndian.PutUint64(ct[8:], ct1)
}

func Decrypt(pt, ct []byte, k []uint64) {
	ct0 := binary.LittleEndian.Uint64(ct[0:])
	ct1 := binary.LittleEndian.Uint64(ct[8:])

	for i := 31; i >= 0; i-- {
		// decryption
		ct0 ^= ct1
		ct0 = bits.RotateLeft64(ct0, -3)
		ct1 ^= k[i]
		ct1 -= ct0
		ct1 = bits.RotateLeft64(ct1, 8)
	}

	binary.LittleEndian.PutUint64(pt[0:], ct0)
	binary.LittleEndian.PutUint64(pt[8:], ct1)
}
