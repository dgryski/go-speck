// +build ignore

package main

import (
	. "github.com/mmcloughlin/avo/build"
	. "github.com/mmcloughlin/avo/operand"
	. "github.com/mmcloughlin/avo/reg"
)

// siphash 1-3
const (
	cROUND = 1
	dROUND = 3
)

func speckRound(x, y Register, k Op) {
	RORQ(Imm(8), x)
	ADDQ(y, x)
	XORQ(k, x)
	ROLQ(Imm(3), y)
	XORQ(x, y)
}

func makeEncryptASM() {
	TEXT("EncryptASM", NOSPLIT, "func(pt, ct, k []uint64)")

	pt := GP64()
	Load(Param("pt").Base(), pt)

	ct0 := GP64()
	ct1 := GP64()
	MOVQ(Mem{Base: pt}, ct0)
	MOVQ(Mem{Base: pt, Disp: 8}, ct1)

	k := GP64()
	Load(Param("k").Base(), k)

	for i := 0; i < 32; i++ {
		speckRound(ct1, ct0, Mem{Base: k, Disp: 8 * i})
	}

	ct := GP64()
	Load(Param("ct").Base(), ct)
	MOVQ(ct0, Mem{Base: ct})
	MOVQ(ct1, Mem{Base: ct, Disp: 8})

	RET()
}

func makeExpandEncryptASM() {
	TEXT("ExpandEncryptASM", NOSPLIT, "func(pt, ct, k []uint64)")

	pt := GP64()
	Load(Param("pt").Base(), pt)

	ct0 := GP64()
	ct1 := GP64()
	MOVQ(Mem{Base: pt}, ct0)
	MOVQ(Mem{Base: pt, Disp: 8}, ct1)

	k := GP64()
	Load(Param("k").Base(), k)

	a := GP64()
	b := GP64()

	MOVQ(Mem{Base: k}, a)
	MOVQ(Mem{Base: k, Disp: 8}, b)

	speckRound(ct1, ct0, a)
	for i := 0; i < 31; i++ {
		speckRound(b, a, Imm(uint64(i)))
		speckRound(ct1, ct0, a)
	}

	ct := GP64()
	Load(Param("ct").Base(), ct)
	MOVQ(ct0, Mem{Base: ct})
	MOVQ(ct1, Mem{Base: ct, Disp: 8})

	RET()
}

func main() {
	Package("github.com/dgryski/go-speck")

	makeEncryptASM()
	makeExpandEncryptASM()

	Generate()
}
