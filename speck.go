// Package speck implements the SPECK block cipher
/*
   https://eprint.iacr.org/2013/404
   http://csrc.nist.gov/groups/ST/lwc-workshop2015/papers/session1-shors-paper.pdf
   https://eprint.iacr.org/2017/560

*/
package speck

func rotl(x uint64, r uint) uint64 {
	return (x << r) | (x >> (64 - r))
}

func rotr(x uint64, r uint) uint64 {
	return (x << (64 - r)) | (x >> r)
}

func ExpandKeyAndEncrypt(pt, ct, K []uint64) {

	B := K[1]
	A := K[0]

	ct0 := pt[0]
	ct1 := pt[1]
	for i := uint64(0); i < 32; i++ {
		// encryption
		ct1 = rotr(ct1, 8)
		ct1 += ct0
		ct1 ^= A
		ct0 = rotl(ct0, 3)
		ct0 ^= ct1

		// inline key expansion phase
		B = rotr(B, 8)
		B += A
		B ^= i
		A = rotl(A, 3)
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
		A = rotr(A, 3)
		B ^= i
		B -= A
		B = rotl(B, 8)

		// decryption
		ct0 ^= ct1
		ct0 = rotr(ct0, 3)
		ct1 ^= A
		ct1 -= ct0
		ct1 = rotl(ct1, 8)
	}

	ct[0] = ct0
	ct[1] = ct1
}

func Encrypt(pt, ct, k []uint64) {
	ct0 := pt[0]
	ct1 := pt[1]

	for i := 0; i < 32; i++ {
		// encryption
		ct1 = rotr(ct1, 8)
		ct1 += ct0
		ct1 ^= k[i]
		ct0 = rotl(ct0, 3)
		ct0 ^= ct1
	}

	ct[0] = ct0
	ct[1] = ct1
}

func Decrypt(pt, ct, k []uint64) {
	ct0 := ct[0]
	ct1 := ct[1]

	for i := 31; i >= 0; i-- {
		// encryption
		ct0 ^= ct1
		ct0 = rotr(ct0, 3)
		ct1 ^= k[i]
		ct1 -= ct0
		ct1 = rotl(ct1, 8)
	}

	pt[0] = ct0
	pt[1] = ct1
}

func ExpandKey(k, K []uint64) {
	l := make([]uint64, 32)

	l[0] = K[1]
	k[0] = K[0]

	for i := uint64(0); i < 32-1; i++ {
		l[i+1] = (k[i] + rotr(l[i], 8)) ^ i
		k[i+1] = rotl(k[i], 3) ^ l[i+1]
	}
}
