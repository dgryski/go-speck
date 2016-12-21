// +build amd64

package speck

//go:generate python -m peachpy.x86_64 speck.py -S -o speck_amd64.s -mabi=goasm
//go:noescape

func EncryptASM(pt, ct, k []uint64)

//go:noescape

func ExpandEncryptASM(pt, ct, K []uint64)
