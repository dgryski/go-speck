// Package speck implements the SPECK block cipher
/*
   https://eprint.iacr.org/2013/404
   http://csrc.nist.gov/groups/ST/lwc-workshop2015/papers/session1-shors-paper.pdf
   https://eprint.iacr.org/2017/560

*/
package speck

import (
	"math/bits"
)

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

func ExpandKeyAndDecrypt(pt, ct, K []uint64) {
	B := K[1]
	A := K[0]

	ct0 := pt[0]
	ct1 := pt[1]
	for i := uint64(0); i < 32; i++ {
		// inline key expansion phase
		A ^= B
		A = bits.RotateLeft64(A, -3)
		B ^= i
		B -= A
		B = bits.RotateLeft64(B, 8)

		// decryption
		ct0 ^= ct1
		ct0 = bits.RotateLeft64(ct0, -3)
		ct1 ^= A
		ct1 -= ct0
		ct1 = bits.RotateLeft64(ct1, 8)
	}

	ct[0] = ct0
	ct[1] = ct1
}

/*
func Encrypt(pt, ct, k []uint64) {
	ct0, ct1, _ := pt[0], pt[1], k[31]

	for i := 0; i < 32; i++ {
		// encryption
		ct1 = bits.RotateLeft64(ct1, -8)
		ct1 += ct0
		ct1 ^= k[i]
		ct0 = bits.RotateLeft64(ct0, 3)
		ct0 ^= ct1
	}

	ct[0], ct[1] = ct0, ct1
}
*/

func Encrypt(pt, ct, k []uint64) {
	ct0, ct1, _ := pt[0], pt[1], k[31]

	ct1 = (bits.RotateLeft64(ct1, -8) + ct0) ^ k[0]
	ct0 = bits.RotateLeft64(ct0, 3) ^ ct1
	ct1 = (bits.RotateLeft64(ct1, -8) + ct0) ^ k[1]
	ct0 = bits.RotateLeft64(ct0, 3) ^ ct1
	ct1 = (bits.RotateLeft64(ct1, -8) + ct0) ^ k[2]
	ct0 = bits.RotateLeft64(ct0, 3) ^ ct1
	ct1 = (bits.RotateLeft64(ct1, -8) + ct0) ^ k[3]
	ct0 = bits.RotateLeft64(ct0, 3) ^ ct1
	ct1 = (bits.RotateLeft64(ct1, -8) + ct0) ^ k[4]
	ct0 = bits.RotateLeft64(ct0, 3) ^ ct1
	ct1 = (bits.RotateLeft64(ct1, -8) + ct0) ^ k[5]
	ct0 = bits.RotateLeft64(ct0, 3) ^ ct1
	ct1 = (bits.RotateLeft64(ct1, -8) + ct0) ^ k[6]
	ct0 = bits.RotateLeft64(ct0, 3) ^ ct1
	ct1 = (bits.RotateLeft64(ct1, -8) + ct0) ^ k[7]
	ct0 = bits.RotateLeft64(ct0, 3) ^ ct1
	ct1 = (bits.RotateLeft64(ct1, -8) + ct0) ^ k[8]
	ct0 = bits.RotateLeft64(ct0, 3) ^ ct1
	ct1 = (bits.RotateLeft64(ct1, -8) + ct0) ^ k[9]
	ct0 = bits.RotateLeft64(ct0, 3) ^ ct1
	ct1 = (bits.RotateLeft64(ct1, -8) + ct0) ^ k[10]
	ct0 = bits.RotateLeft64(ct0, 3) ^ ct1
	ct1 = (bits.RotateLeft64(ct1, -8) + ct0) ^ k[11]
	ct0 = bits.RotateLeft64(ct0, 3) ^ ct1
	ct1 = (bits.RotateLeft64(ct1, -8) + ct0) ^ k[12]
	ct0 = bits.RotateLeft64(ct0, 3) ^ ct1
	ct1 = (bits.RotateLeft64(ct1, -8) + ct0) ^ k[13]
	ct0 = bits.RotateLeft64(ct0, 3) ^ ct1
	ct1 = (bits.RotateLeft64(ct1, -8) + ct0) ^ k[14]
	ct0 = bits.RotateLeft64(ct0, 3) ^ ct1
	ct1 = (bits.RotateLeft64(ct1, -8) + ct0) ^ k[15]
	ct0 = bits.RotateLeft64(ct0, 3) ^ ct1
	ct1 = (bits.RotateLeft64(ct1, -8) + ct0) ^ k[16]
	ct0 = bits.RotateLeft64(ct0, 3) ^ ct1
	ct1 = (bits.RotateLeft64(ct1, -8) + ct0) ^ k[17]
	ct0 = bits.RotateLeft64(ct0, 3) ^ ct1
	ct1 = (bits.RotateLeft64(ct1, -8) + ct0) ^ k[18]
	ct0 = bits.RotateLeft64(ct0, 3) ^ ct1
	ct1 = (bits.RotateLeft64(ct1, -8) + ct0) ^ k[19]
	ct0 = bits.RotateLeft64(ct0, 3) ^ ct1
	ct1 = (bits.RotateLeft64(ct1, -8) + ct0) ^ k[20]
	ct0 = bits.RotateLeft64(ct0, 3) ^ ct1
	ct1 = (bits.RotateLeft64(ct1, -8) + ct0) ^ k[21]
	ct0 = bits.RotateLeft64(ct0, 3) ^ ct1
	ct1 = (bits.RotateLeft64(ct1, -8) + ct0) ^ k[22]
	ct0 = bits.RotateLeft64(ct0, 3) ^ ct1
	ct1 = (bits.RotateLeft64(ct1, -8) + ct0) ^ k[23]
	ct0 = bits.RotateLeft64(ct0, 3) ^ ct1
	ct1 = (bits.RotateLeft64(ct1, -8) + ct0) ^ k[24]
	ct0 = bits.RotateLeft64(ct0, 3) ^ ct1
	ct1 = (bits.RotateLeft64(ct1, -8) + ct0) ^ k[25]
	ct0 = bits.RotateLeft64(ct0, 3) ^ ct1
	ct1 = (bits.RotateLeft64(ct1, -8) + ct0) ^ k[26]
	ct0 = bits.RotateLeft64(ct0, 3) ^ ct1
	ct1 = (bits.RotateLeft64(ct1, -8) + ct0) ^ k[27]
	ct0 = bits.RotateLeft64(ct0, 3) ^ ct1
	ct1 = (bits.RotateLeft64(ct1, -8) + ct0) ^ k[28]
	ct0 = bits.RotateLeft64(ct0, 3) ^ ct1
	ct1 = (bits.RotateLeft64(ct1, -8) + ct0) ^ k[29]
	ct0 = bits.RotateLeft64(ct0, 3) ^ ct1
	ct1 = (bits.RotateLeft64(ct1, -8) + ct0) ^ k[30]
	ct0 = bits.RotateLeft64(ct0, 3) ^ ct1
	ct1 = (bits.RotateLeft64(ct1, -8) + ct0) ^ k[31]
	ct0 = bits.RotateLeft64(ct0, 3) ^ ct1

	ct[0], ct[1] = ct0, ct1
}

/*
func decrypt(pt, ct, k []uint64) {
	ct0, ct1, _ := ct[0], ct[1], k[31]

	for i := 31; i >= 0; i-- {
		// encryption
		ct0 ^= ct1
		ct0 = bits.RotateLeft64(ct0, -3)
		ct1 ^= k[i]
		ct1 -= ct0
		ct1 = bits.RotateLeft64(ct1, 8)
	}

	pt[0], pt[1] = ct0, ct1
}
*/

func Decrypt(pt, ct, k []uint64) {
	ct0, ct1, _ := ct[0], ct[1], k[31]

	ct0 = bits.RotateLeft64(ct0^ct1, -3)
	ct1 = bits.RotateLeft64(ct1^k[31]-ct0, 8)
	ct0 = bits.RotateLeft64(ct0^ct1, -3)
	ct1 = bits.RotateLeft64(ct1^k[30]-ct0, 8)
	ct0 = bits.RotateLeft64(ct0^ct1, -3)
	ct1 = bits.RotateLeft64(ct1^k[29]-ct0, 8)
	ct0 = bits.RotateLeft64(ct0^ct1, -3)
	ct1 = bits.RotateLeft64(ct1^k[28]-ct0, 8)
	ct0 = bits.RotateLeft64(ct0^ct1, -3)
	ct1 = bits.RotateLeft64(ct1^k[27]-ct0, 8)
	ct0 = bits.RotateLeft64(ct0^ct1, -3)
	ct1 = bits.RotateLeft64(ct1^k[26]-ct0, 8)
	ct0 = bits.RotateLeft64(ct0^ct1, -3)
	ct1 = bits.RotateLeft64(ct1^k[25]-ct0, 8)
	ct0 = bits.RotateLeft64(ct0^ct1, -3)
	ct1 = bits.RotateLeft64(ct1^k[24]-ct0, 8)
	ct0 = bits.RotateLeft64(ct0^ct1, -3)
	ct1 = bits.RotateLeft64(ct1^k[23]-ct0, 8)
	ct0 = bits.RotateLeft64(ct0^ct1, -3)
	ct1 = bits.RotateLeft64(ct1^k[22]-ct0, 8)
	ct0 = bits.RotateLeft64(ct0^ct1, -3)
	ct1 = bits.RotateLeft64(ct1^k[21]-ct0, 8)
	ct0 = bits.RotateLeft64(ct0^ct1, -3)
	ct1 = bits.RotateLeft64(ct1^k[20]-ct0, 8)
	ct0 = bits.RotateLeft64(ct0^ct1, -3)
	ct1 = bits.RotateLeft64(ct1^k[19]-ct0, 8)
	ct0 = bits.RotateLeft64(ct0^ct1, -3)
	ct1 = bits.RotateLeft64(ct1^k[18]-ct0, 8)
	ct0 = bits.RotateLeft64(ct0^ct1, -3)
	ct1 = bits.RotateLeft64(ct1^k[17]-ct0, 8)
	ct0 = bits.RotateLeft64(ct0^ct1, -3)
	ct1 = bits.RotateLeft64(ct1^k[16]-ct0, 8)
	ct0 = bits.RotateLeft64(ct0^ct1, -3)
	ct1 = bits.RotateLeft64(ct1^k[15]-ct0, 8)
	ct0 = bits.RotateLeft64(ct0^ct1, -3)
	ct1 = bits.RotateLeft64(ct1^k[14]-ct0, 8)
	ct0 = bits.RotateLeft64(ct0^ct1, -3)
	ct1 = bits.RotateLeft64(ct1^k[13]-ct0, 8)
	ct0 = bits.RotateLeft64(ct0^ct1, -3)
	ct1 = bits.RotateLeft64(ct1^k[12]-ct0, 8)
	ct0 = bits.RotateLeft64(ct0^ct1, -3)
	ct1 = bits.RotateLeft64(ct1^k[11]-ct0, 8)
	ct0 = bits.RotateLeft64(ct0^ct1, -3)
	ct1 = bits.RotateLeft64(ct1^k[10]-ct0, 8)
	ct0 = bits.RotateLeft64(ct0^ct1, -3)
	ct1 = bits.RotateLeft64(ct1^k[9]-ct0, 8)
	ct0 = bits.RotateLeft64(ct0^ct1, -3)
	ct1 = bits.RotateLeft64(ct1^k[8]-ct0, 8)
	ct0 = bits.RotateLeft64(ct0^ct1, -3)
	ct1 = bits.RotateLeft64(ct1^k[7]-ct0, 8)
	ct0 = bits.RotateLeft64(ct0^ct1, -3)
	ct1 = bits.RotateLeft64(ct1^k[6]-ct0, 8)
	ct0 = bits.RotateLeft64(ct0^ct1, -3)
	ct1 = bits.RotateLeft64(ct1^k[5]-ct0, 8)
	ct0 = bits.RotateLeft64(ct0^ct1, -3)
	ct1 = bits.RotateLeft64(ct1^k[4]-ct0, 8)
	ct0 = bits.RotateLeft64(ct0^ct1, -3)
	ct1 = bits.RotateLeft64(ct1^k[3]-ct0, 8)
	ct0 = bits.RotateLeft64(ct0^ct1, -3)
	ct1 = bits.RotateLeft64(ct1^k[2]-ct0, 8)
	ct0 = bits.RotateLeft64(ct0^ct1, -3)
	ct1 = bits.RotateLeft64(ct1^k[1]-ct0, 8)
	ct0 = bits.RotateLeft64(ct0^ct1, -3)
	ct1 = bits.RotateLeft64(ct1^k[0]-ct0, 8)

	pt[0], pt[1] = ct0, ct1
}

func ExpandKey(k, K []uint64) {
	l := make([]uint64, 32)

	l[0] = K[1]
	k[0] = K[0]

	for i := uint64(0); i < 32-1; i++ {
		l[i+1] = (k[i] + bits.RotateLeft64(l[i], -8)) ^ i
		k[i+1] = bits.RotateLeft64(k[i], 3) ^ l[i+1]
	}
}
