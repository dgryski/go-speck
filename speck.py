import peachpy.x86_64

pt_base = Argument(ptr())
pt_len = Argument(int64_t)
pt_cap = Argument(int64_t)

ct_base = Argument(ptr())
ct_len = Argument(int64_t)
ct_cap = Argument(int64_t)

k_base = Argument(ptr())
k_len = Argument(int64_t)
k_cap = Argument(int64_t)

def speckRound(x,y,k):
    ROR(x, 8)
    ADD(x, y)
    XOR(x, k)
    ROL(y, 3)
    XOR(y, x)

with Function("EncryptASM", (pt_base, pt_len, pt_cap, ct_base, ct_len, ct_cap, k_base, k_len, k_cap), target=uarch.default) as function:
    pt = GeneralPurposeRegister64()
    LOAD.ARGUMENT(pt, pt_base)

    ct0 = GeneralPurposeRegister64()
    ct1 = GeneralPurposeRegister64()
    MOV(ct0, [pt])
    MOV(ct1, [pt+8])

    k = GeneralPurposeRegister64()

    LOAD.ARGUMENT(k, k_base)

    for i in range(32):
        speckRound(ct1, ct0, [k+8*i])

    ct = GeneralPurposeRegister64()
    LOAD.ARGUMENT(ct, ct_base)
    MOV([ct], ct0)
    MOV([ct+8], ct1)

    RETURN()

with Function("ExpandEncryptASM", (pt_base, pt_len, pt_cap, ct_base, ct_len, ct_cap, k_base, k_len, k_cap), target=uarch.default) as function:
    pt = GeneralPurposeRegister64()
    LOAD.ARGUMENT(pt, pt_base)

    ct0 = GeneralPurposeRegister64()
    ct1 = GeneralPurposeRegister64()
    MOV(ct0, [pt])
    MOV(ct1, [pt+8])

    k = GeneralPurposeRegister64()
    LOAD.ARGUMENT(k, k_base)

    a = GeneralPurposeRegister64()
    b = GeneralPurposeRegister64()
    MOV(a, [k])
    MOV(b, [k+8])

    speckRound(ct1, ct0, a)
    for i in range(31):
        speckRound(b, a, i)
        speckRound(ct1, ct0, a)

    ct = GeneralPurposeRegister64()
    LOAD.ARGUMENT(ct, ct_base)
    MOV([ct], ct0)
    MOV([ct+8], ct1)

    RETURN()

