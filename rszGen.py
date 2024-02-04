import collections
import hashlib
import random
import os
import sys

EllipticCurve_1 = collections.namedtuple('EllipticCurve', 'name p a b g n h')

curve = EllipticCurve_1(
    'secp256k1',
    # Field characteristic.
    p=0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f,
    # Curve coefficients.
    a=0,
    b=7,
    # Base point.
    g=(0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
       0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8),
    # Subgroup order.
    n=0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141,
    # Subgroup cofactor.
    h=1,
)


# Modular arithmetic ##########################################################


def decToHexa(n):
  return hex(n).replace("0x","")

def inverse_mod(k, p):
    """Returns the inverse of k modulo p.
    This function returns the only integer x such that (x * k) % p == 1.
    k must be non-zero and p must be a prime.
    """
    if k == 0:
        raise ZeroDivisionError('division by zero')

    if k < 0:
        # k ** -1 = p - (-k) ** -1  (mod p)
        return p - inverse_mod(-k, p)

    # Extended Euclidean algorithm.
    s, old_s = 0, 1
    t, old_t = 1, 0
    r, old_r = p, k

    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t

    gcd, x, y = old_r, old_s, old_t

    assert gcd == 1
    assert (k * x) % p == 1

    return x % p


# Functions that work on curve points #########################################

def is_on_curve(point):
    """Returns True if the given point lies on the elliptic curve."""
    if point is None:
        # None represents the point at infinity.
        return True

    x, y = point

    return (y * y - x * x * x - curve.a * x - curve.b) % curve.p == 0


def point_neg(point):
    """Returns -point."""
    assert is_on_curve(point)

    if point is None:
        # -0 = 0
        return None

    x, y = point
    result = (x, -y % curve.p)

    assert is_on_curve(result)

    return result


def point_add(point1, point2):
    """Returns the result of point1 + point2 according to the group law."""
    assert is_on_curve(point1)
    assert is_on_curve(point2)

    if point1 is None:
        # 0 + point2 = point2
        return point2
    if point2 is None:
        # point1 + 0 = point1
        return point1

    x1, y1 = point1
    x2, y2 = point2

    if x1 == x2 and y1 != y2:
        # point1 + (-point1) = 0
        return None

    if x1 == x2:
        # This is the case point1 == point2.
        m = (3 * x1 * x1 + curve.a) * inverse_mod(2 * y1, curve.p)
    else:
        # This is the case point1 != point2.
        m = (y1 - y2) * inverse_mod(x1 - x2, curve.p)

    x3 = m * m - x1 - x2
    y3 = y1 + m * (x3 - x1)
    result = (x3 % curve.p,
              -y3 % curve.p)

    assert is_on_curve(result)

    return result


def scalar_mult(k, point):
    """Returns k * point computed using the double and point_add algorithm."""
    assert is_on_curve(point)

    if k % curve.n == 0 or point is None:
        return None

    if k < 0:
        # k * point = -k * (-point)
        return scalar_mult(-k, point_neg(point))

    result = None
    addend = point

    while k:
        if k & 1:
            # Add.
            result = point_add(result, addend)

        # Double.
        addend = point_add(addend, addend)

        k >>= 1

    assert is_on_curve(result)

    return result


# Keypair generation and ECDSA ################################################

def make_keypair(private):
    """Generates a random private-public key pair."""
    private_key = private#random.randrange(1, curve.n)
    public_key = scalar_mult(private_key, curve.g)

    return private_key, public_key


def hash_message(message):
    """Returns the truncated SHA512 hash of the message."""
    message_hash = hashlib.sha512(message).digest()
    e = int.from_bytes(message_hash, 'big')

    # FIPS 180 says that when a hash needs to be truncated, the rightmost bits
    # should be discarded.
    z = e >> (e.bit_length() - curve.n.bit_length())

    assert z.bit_length() <= curve.n.bit_length()

    return z


def sign_message(private_key, message,nonce):
    z = hash_message(message)

    r = 0
    s = 0
    half_mod=57896044618658097711785492504343953926418782139537452191302581570759080747169
   
    while not r or not s:
        k = nonce# random.randrange(1, curve.n)
        x, y = scalar_mult(k, curve.g)

        r = x % curve.n
        s = ((z + r * private_key) * inverse_mod(k, curve.n)) % curve.n
        if s> half_mod:
            s=curve.n -s
        if s<0:
            s=s%curve.n
   
     
    return r, s,z

def verify_signature(public_key, message, signature):
    z=message
   
    r, s = signature

    w = inverse_mod(s, curve.n)
    u1 = (z * w) % curve.n
    u2 = (r * w) % curve.n

    x, y = point_add(scalar_mult(u1, curve.g),
                     scalar_mult(u2, public_key))

    if (r % curve.n) == (x % curve.n):
        return 'signature matches'
    else:
        return 'invalid signature'

def egcd(a, b):
    "Euclidean greatest common divisor"
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    "Modular inverse"
    # in Python 3.8 you can simply return pow(a,-1,m)
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

   
sourceFile = open('file.txt', 'w')
   
def make_val(priv,nonce,msg,id):   

        private, public = make_keypair(priv)
         
        r,s,z = sign_message(private, msg,nonce)
        print()
        print("tra"+str(id)+"=", id)
        print("r"+str(id)+"=",decToHexa(r))
        print("s"+str(id)+"=",decToHexa(s)) 
        print("z"+str(id)+"=",decToHexa(z))
        print(decToHexa(r),",",decToHexa(s),",",decToHexa(z),sep="",file = sourceFile)
        
  
        return private,public,nonce,r,s,z
 
   


a=2**148                                            
c=2**248  


                        
hexkey = input('Privatekey hex: ')    
priv = int(hexkey, 16)
print()
print("Calculating RSZ Pairs for Priv", hexkey)


for i in range(1, 80):
    priv=priv
    nonce=random.randrange(a,c)
    war= str(os.urandom(25)) + str(nonce)         
    msg= bytes(war, 'utf-8')
    make_val(priv,nonce,msg,i) 
    
    
sourceFile.close()


print()   
print(i,"RSZ SAVED IN OUTPUT FILE")



