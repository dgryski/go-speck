package speck

// hardcoded until https://github.com/golang/go/issues/18254 is fixed

// left circular shift
func rotl3(x uint64) uint64 {
	const r = 3
	return (x << r) | (x >> (64 - r))
}

func rotr3(x uint64) uint64 {
	const r = 3
	return (x << (64 - r)) | (x >> r)
}

// right circular shift
func rotr8(x uint64) uint64 {
	const r = 8
	return (x << (64 - r)) | (x >> r)
}

func rotl8(x uint64) uint64 {
	const r = 8
	return (x << r) | (x >> (64 - r))
}

func ExpandKeyAndEncrypt(pt, ct, K []uint64) {

	B := K[1]
	A := K[0]

	ct0 := pt[0]
	ct1 := pt[1]
	for i := uint64(0); i < 32; i++ {
		// encryption
		ct1 = rotr8(ct1)
		ct1 += ct0
		ct1 ^= A
		ct0 = rotl3(ct0)
		ct0 ^= ct1

		// inline key expansion phase
		B = rotr8(B)
		B += A
		B ^= i
		A = rotl3(A)
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
		A = rotr3(A)
		B ^= i
		B -= A
		B = rotl8(B)

		// decryption
		ct0 ^= ct1
		ct0 = rotr3(ct0)
		ct1 ^= A
		ct1 -= ct0
		ct1 = rotl8(ct1)
	}

	ct[0] = ct0
	ct[1] = ct1
}

func Encrypt(pt, ct, k []uint64) {
	ct0 := pt[0]
	ct1 := pt[1]

	for i := 0; i < 32; i++ {
		// encryption
		ct1 = rotr8(ct1)
		ct1 += ct0
		ct1 ^= k[i]
		ct0 = rotl3(ct0)
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
		ct0 = rotr3(ct0)
		ct1 ^= k[i]
		ct1 -= ct0
		ct1 = rotl8(ct1)
	}

	pt[0] = ct0
	pt[1] = ct1
}

func ExpandKey(k, K []uint64) {
	l := make([]uint64, 32)

	l[0] = K[1]
	k[0] = K[0]

	for i := uint64(0); i < 32-1; i++ {
		l[i+1] = (k[i] + rotr8(l[i])) ^ i
		k[i+1] = rotl3(k[i]) ^ l[i+1]
	}
}
