//go:build amd64
// +build amd64

package speck

//go:generate go run asm.go -out speck_amd64.s
//go:noescape

func EncryptASM(pt, ct, k []uint64)

//go:noescape

func DecryptASM(pt, ct, k []uint64)

//go:noescape

func ExpandEncryptASM(pt, ct, k []uint64)
