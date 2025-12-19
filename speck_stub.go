//go:build amd64 && !purego

package speck

//go:generate go run asm.go -out speck_amd64.s
//go:noescape

func Encrypt(pt, ct, k []uint64)

//go:noescape

func Decrypt(pt, ct, k []uint64)

//go:noescape

func ExpandKeyAndEncrypt(pt, ct, k []uint64)
