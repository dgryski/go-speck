//go:build ignore
// +build ignore

package main

import (
	. "github.com/mmcloughlin/avo/build"
	. "github.com/mmcloughlin/avo/operand"
	. "github.com/mmcloughlin/avo/reg"
)

func speckRound(x, y Register, k Op) {
	RORQ(Imm(8), x)
	ADDQ(y, x)
	XORQ(k, x)
	ROLQ(Imm(3), y)
	XORQ(x, y)
}

func speckUnround(x, y Register, k Op) {
	XORQ(x, y)
	RORQ(Imm(3), y)
	XORQ(k, x)
	SUBQ(y, x)
	ROLQ(Imm(8), x)
}

func makeEncrypt() {
	TEXT("encryptCore", NOSPLIT, "func(pt, ct, k []uint64)")

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

func makeDecrypt() {
	TEXT("decryptCore", NOSPLIT, "func(pt, ct, k []uint64)")

	ct := GP64()
	Load(Param("ct").Base(), ct)

	ct0 := GP64()
	ct1 := GP64()
	MOVQ(Mem{Base: ct}, ct0)
	MOVQ(Mem{Base: ct, Disp: 8}, ct1)

	k := GP64()
	Load(Param("k").Base(), k)

	for i := 31; i >= 0; i-- {
		speckUnround(ct1, ct0, Mem{Base: k, Disp: 8 * i})
	}

	pt := GP64()
	Load(Param("pt").Base(), pt)
	MOVQ(ct0, Mem{Base: pt})
	MOVQ(ct1, Mem{Base: pt, Disp: 8})

	RET()
}

func main() {
	Package("github.com/dgryski/go-speck")

	ConstraintExpr("!purego")

	makeEncrypt()
	makeDecrypt()

	Generate()
}
