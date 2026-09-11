"""Print the 256 secp256k1 X/Y pairs using independent affine arithmetic.
Requires Python 3.8+; no production code or third-party packages are used.
"""
p = 2**256 - 2**32 - 977
x = int('79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798', 16)
y = int('483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8', 16)
for _ in range(256):
    print(f'{x:064x} {y:064x}')
    slope = 3 * x*x * pow(2*y, -1, p) % p
    nx = (slope*slope - 2*x) % p
    y = (slope*(x-nx) - y) % p
    x = nx
