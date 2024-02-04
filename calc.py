import random

def h(n):
    return hex(n).replace("0x", "")

def extended_gcd(aa, bb):
    lastremainder, remainder = abs(aa), abs(bb)
    x, lastx, y, lasty = 0, 1, 1, 0
    while remainder:
        lastremainder, (quotient, remainder) = remainder, divmod(lastremainder, remainder)
        x, lastx = lastx - quotient * x, x
        y, lasty = lasty - quotient * y, y
    return lastremainder, lastx * (-1 if aa < 0 else 1), lasty * (-1 if bb < 0 else 1)

def modinv(a, m):
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise ValueError
    return x % m

N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141

R = 0x1
S = 0x1
Z = 0x1

with open("daten.txt", "w") as file:
    for _ in range(1000000):
        K = random.randint(100000000000000000000000000000000000000000000000000000000000000000000000000000, 115792089237316195423570985008687907852837564279074904382605163141518161494336)
        result = h((((S * K) - Z) * modinv(R, N)) % N)
        file.write(result + "\n")
