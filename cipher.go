// Package speck implements the SPECK block cipher
/*
   https://eprint.iacr.org/2013/404
   http://csrc.nist.gov/groups/ST/lwc-workshop2015/papers/session1-shors-paper.pdf
   https://eprint.iacr.org/2017/560
   https://nsacyber.github.io/simon-speck/
*/
package speck

import (
	"crypto/cipher"
	"encoding/binary"
	"math/bits"
	"strconv"
)

type speck128128 struct {
	keys [32]uint64
}

const BlockSize = 16

type KeySizeError int

func (k KeySizeError) Error() string { return "speck: invalid key size " + strconv.Itoa(int(k)) }

func New(key []byte) (cipher.Block, error) {

	if l := len(key); l != 16 {
		return nil, KeySizeError(l)
	}

	var s speck128128

	expandKey(s.keys[:], key)

	return &s, nil
}

func (speck128128) BlockSize() int { return BlockSize }

func (s *speck128128) Encrypt(dst, src []byte) {
	encryptCore(src, dst, s.keys[:])
}

func (s *speck128128) Decrypt(dst, src []byte) {
	decryptCore(dst, src, s.keys[:])
}

func expandKey(k []uint64, K []byte) {
	l := make([]uint64, 32)

	l[0] = binary.LittleEndian.Uint64(K[8:])
	k[0] = binary.LittleEndian.Uint64(K[0:])

	for i := uint64(0); i < 32-1; i++ {
		l[i+1] = (k[i] + bits.RotateLeft64(l[i], -8)) ^ i
		k[i+1] = bits.RotateLeft64(k[i], 3) ^ l[i+1]
	}
}
