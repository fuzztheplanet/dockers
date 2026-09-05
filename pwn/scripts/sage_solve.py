#!/usr/bin/env python3
from sage.all import *


def modular_examples():
    p = 0xfffffffffffffffffffffffffffffffeffffffffffffffff
    a = 1234567
    print("[*] a^-1 mod p =", hex(inverse_mod(a, p)))
    print("[*] sqrt in GF(p):", GF(p)(4).sqrt())


def crt_example():
    residues, moduli = [2, 3, 2], [3, 5, 7]
    x = crt(residues, moduli)
    print("[*] CRT x =", x, "mod", prod(moduli))
    return x


def linear_system():
    # exact solve of A x = b over the rationals
    A = Matrix(QQ, [[2, 1], [1, 3]])
    b = vector(QQ, [5, 10])
    x = A.solve_right(b)
    print("[*] system solution =", x)
    return x


def lll_example():
    # LLL for hidden-number / LCG problems: build the basis from the challenge
    # relations, the shortest reduced row usually holds the secret.
    B = Matrix(ZZ, [
        [1, 0, 12345],
        [0, 1, 67890],
        [0, 0, 99991],
    ])
    reduced = B.LLL()
    print("[*] LLL-reduced basis:")
    print(reduced)
    print("[*] shortest row:", reduced[0])
    return reduced


if __name__ in ("__main__", "sage.all"):
    modular_examples()
    crt_example()
    linear_system()
    lll_example()
