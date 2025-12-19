package speck

import (
	"crypto/cipher"
	"encoding/binary"
	"math/bits"
)

type speck64128 struct {
	keys [27]uint32
}

func New64(key []byte) (cipher.Block, error) {

	if l := len(key); l != 16 {
		return nil, KeySizeError(l)
	}

	var s speck64128

	expandKey64(s.keys[:], key)

	return &s, nil
}

func (speck64128) BlockSize() int { return 8 }

func (s *speck64128) Encrypt(dst, src []byte) {
	encrypt64Core(src, dst, s.keys[:])
}

func (s *speck64128) Decrypt(dst, src []byte) {
	decrypt64Core(dst, src, s.keys[:])
}

func encrypt64Core(pt, ct []byte, k []uint32) {
	ct0 := binary.LittleEndian.Uint32(pt[0:])
	ct1 := binary.LittleEndian.Uint32(pt[4:])

	for i := 0; i < 27; i++ {
		ct1, ct0 = encrypt64Round(ct1, ct0, k[i])
	}

	binary.LittleEndian.PutUint32(ct[0:], ct0)
	binary.LittleEndian.PutUint32(ct[4:], ct1)
}

func decrypt64Core(pt, ct []byte, k []uint32) {
	ct0 := binary.LittleEndian.Uint32(ct[0:])
	ct1 := binary.LittleEndian.Uint32(ct[4:])

	for i := 26; i >= 0; i-- {
		ct1, ct0 = decrypt64Round(ct1, ct0, k[i])
	}

	binary.LittleEndian.PutUint32(pt[0:], ct0)
	binary.LittleEndian.PutUint32(pt[4:], ct1)
}

func encrypt64Round(x, y, k uint32) (uint32, uint32) {
	x = bits.RotateLeft32(x, -8)
	x += y
	x ^= k
	y = bits.RotateLeft32(y, 3)
	y ^= x
	return x, y
}

func decrypt64Round(x, y, k uint32) (uint32, uint32) {
	y ^= x
	y = bits.RotateLeft32(y, -3)
	x ^= k
	x -= y
	x = bits.RotateLeft32(x, 8)
	return x, y
}

func expandKey64(k []uint32, K []byte) {
	a, b, c, d := binary.LittleEndian.Uint32(K[0:]), binary.LittleEndian.Uint32(K[4:]), binary.LittleEndian.Uint32(K[8:]), binary.LittleEndian.Uint32(K[12:])

	i := uint32(0)
	for i < 27 {
		k[i] = a
		b, a = encrypt64Round(b, a, i)
		i++

		k[i] = a
		c, a = encrypt64Round(c, a, i)
		i++

		k[i] = a
		d, a = encrypt64Round(d, a, i)
		i++
	}
}
