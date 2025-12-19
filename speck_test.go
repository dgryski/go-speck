package speck

import (
	"crypto/aes"
	"encoding/hex"
	"reflect"
	"testing"

	skipjack "github.com/dgryski/go-skipjack"
)

func unpackHex(s string) []byte {
	dst, _ := hex.DecodeString(s)
	return dst
}

func TestCipher(t *testing.T) {
	var tests = []struct {
		key    string
		plain  string
		cipher string
	}{
		{
			"000102030405060708090a0b0c0d0e0f",
			"206d616465206974206571756976616c",
			"180d575cdffe60786532787951985da6",
		},
	}

	for _, tt := range tests {
		k64 := unpackHex(tt.key)
		p64 := unpackHex(tt.plain)
		want := unpackHex(tt.cipher)

		c, err := New(k64)
		if err != nil {
			t.Fatalf("error constructing cipher: %v", err)
		}

		got := make([]byte, BlockSize)
		c.Encrypt(got, p64)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("c.Encrypt(...)=%x, want %x", got, want)
		}

		c.Decrypt(got, want)
		if !reflect.DeepEqual(got, p64) {
			t.Errorf("c.Decrypt(...)=%x, want %x", got, p64)
		}
	}
}

var sink uint64

func BenchmarkSpeckEncrypt(b *testing.B) {

	k := make([]uint64, 32)
	p := make([]byte, 16)
	c := make([]byte, 16)

	n := b.N / 2

	for i := 0; i < n; i++ {
		encryptCore(p, c, k)
		encryptCore(c, p, k)
	}

	sink += uint64(c[0])
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
