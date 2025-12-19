package speck

import (
	"reflect"
	"testing"
)

func TestCipher64(t *testing.T) {

	var tests = []struct {
		key    string
		plain  string
		cipher string
	}{
		{
			"0001020308090a0b1011121318191a1b",
			"2d4375747465723b",
			"8b024e4548a56f8c",
		},
	}

	for _, tt := range tests {

		k32 := unpackHex(tt.key)
		p32 := unpackHex(tt.plain)
		want := unpackHex(tt.cipher)

		c, _ := New64(k32)

		got := make([]byte, 8)
		c.Encrypt(got, p32)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("c.Encrypt(...)=%x, want %x", got, want)
		}

		c.Decrypt(got, want)
		if !reflect.DeepEqual(got, p32) {
			t.Errorf("c.Decrypt(...)=%x, want %x", got, p32)
		}
	}
}

var sink32 uint32

func BenchmarkSpeck64Encrypt(b *testing.B) {

	k := make([]uint32, 27)
	p := make([]byte, 8)
	c := make([]byte, 8)

	for i := 0; i < b.N; i++ {
		encrypt64Core(p, c, k)
	}

	sink32 += uint32(c[0])
}
