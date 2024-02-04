import ecdsa
from hashlib import sha256
import struct

# Parametry krzywej eliptycznej
p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
a = 0
b = 7
G = ecdsa.SECP256k1.generator
#n = ecdsa.SECP256k1.order
n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
# Funkcje pomocnicze
def bytes_to_long(s):
    acc = 0
    unpack = struct.unpack
    length = len(s)
    if length % 4:
        extra = (4 - length % 4)
        s = b'\000' * extra + s
        length = length + extra
    for i in range(0, length, 4):
        acc = (acc << 32) + unpack('>I', s[i:i+4])[0]
    return acc

def H(m):
    h = sha256()
    h.update(m)
    return bytes_to_long(h.digest())

# Funkcje do podpisywania i weryfikowania
def sign(m, k, d):
    kG = k * G
    r = kG.x()
    s = (H(m) + d * r) * pow(k, -1, n) % n
    return int(r), int(s), H(m)

def calc_x(k_key, r, s, z):
    x = (s * k_key - z) * pow(r, -1, n) % n
    return x, n - x

def calc_k(private, r, s, z):
    k = (r * private + z) * pow(s, -1, n) % n
    return k, n - k

# Przykłady użycia
m1 = b"bitcoin"
k_key = 100
private = 25
r, s, z = sign(m1, k_key, private)
print("1 rsz", r, s, z)
print("k_key=", calc_k(private, int(r), int(s), int(z)))
print("private=", calc_x(k_key, int(r), int(s), int(z)))

# Nowe wartości
r2 = 105562457083132745572708143974180364633865373973280165462544121334166431725102
s2 = 103297023888398300822393645768628709580138523147555505327497101680694113007481
z2 = 48363072098642544965975966934959923879938723004602706934166367375051848994308

print("k_key=", calc_k(private, int(r2), int(s2), int(z2)))
print("private=", calc_x(k_key, int(r2), int(s2), int(z2)))

# Test
print("r==r2", r == r2)
