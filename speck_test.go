package speck

import (
	"crypto/aes"
	"encoding/binary"
	"encoding/hex"
	"reflect"
	"testing"

	skipjack "github.com/dgryski/go-skipjack"
)

func unpack2x64(s string) []uint64 {
	dst := make([]uint64, 2)
	s8, _ := hex.DecodeString(s)

	// test vectors are oddly backwards in the paper
	dst[1] = binary.BigEndian.Uint64(s8[0:])
	dst[0] = binary.BigEndian.Uint64(s8[8:])

	return dst
}

func Test(t *testing.T) {

	var tests = []struct {
		key    string
		plain  string
		cipher string
	}{
		{
			"0f0e0d0c0b0a09080706050403020100",
			"6c617669757165207469206564616d20",
			"a65d9851797832657860fedf5c570d18",
		},
	}

	for _, tt := range tests {

		k64 := unpack2x64(tt.key)
		p64 := unpack2x64(tt.plain)
		want := unpack2x64(tt.cipher)

		got := make([]uint64, 2)

		ExpandKeyAndEncrypt(p64, got, k64)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("ExpandKeyAndEncrypt(...)=%x, want %x", got, want)
		}

		rk := make([]uint64, 32)

		ExpandKey(rk, k64)
		Encrypt(p64, got, rk)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("Encrypt(...)=%x, want %x", got, want)
		}

		p := make([]uint64, 2)

		Decrypt(p, got, rk)
		if !reflect.DeepEqual(p, p64) {
			t.Errorf("Decrypt(...)=%x, want %x", p, p64)
		}
	}
}

var sink uint64

func BenchmarkSpeckExpandEncrypt(b *testing.B) {

	k := make([]uint64, 2)
	p := make([]uint64, 2)
	c := make([]uint64, 2)

	for i := 0; i < b.N; i++ {
		ExpandKeyAndEncrypt(p, c, k)
	}

	sink += c[0]
}

func BenchmarkSpeckEncrypt(b *testing.B) {

	k := make([]uint64, 32)
	p := make([]uint64, 2)
	c := make([]uint64, 2)

	for i := 0; i < b.N; i++ {
		Encrypt(p, c, k)
	}

	sink += c[0]
}

// TEA, from https://en.wikipedia.org/wiki/Tiny_Encryption_Algorithm
func teaEncrypt(v, k []uint32) {
	v0 := v[0]
	v1 := v[1]
	var sum uint32

	var delta uint32 = 0x9e3779b9

	k0, k1, k2, k3 := k[0], k[1], k[2], k[3]

	for i := 0; i < 32; i++ {
		sum += delta
		v0 += ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1)
		v1 += ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3)
	}
	v[0] = v0
	v[1] = v1
}

func BenchmarkTEA(b *testing.B) {

	k := make([]uint32, 4)
	p := make([]uint32, 2)

	for i := 0; i < b.N; i++ {
		teaEncrypt(p, k)
	}

	sink += uint64(p[0])
}

func BenchmarkSKIPJACK(b *testing.B) {

	k := make([]byte, 10)
	p := make([]byte, 8)

	c, _ := skipjack.New(k)

	for i := 0; i < b.N; i++ {
		c.Encrypt(p, p)
	}

	sink += uint64(p[0])
}

func BenchmarkAES(b *testing.B) {

	k := make([]byte, 16)

	cipher, _ := aes.NewCipher(k)

	p := make([]byte, 16)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		cipher.Encrypt(p, p)
	}

	sink += uint64(p[0])
}
