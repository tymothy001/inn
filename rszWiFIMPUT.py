#!/usr/bin/env python
import hashlib
import sys

p  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

params = {'p': p}

def hexify(s, flip=False):
    if flip:
        return s[::-1].hex()
    else:
        return s.hex()

def unhexify(s, flip=False):
    if flip:
        return bytes.fromhex(s)[::-1]
    else:
        return bytes.fromhex(s)

def inttohexstr(i):
    tmpstr = hex(i)
    hexstr = tmpstr.replace('0x','').replace('L','').zfill(64)
    return hexstr

b58_digits = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def dhash(s):
    return hashlib.sha256(hashlib.sha256(s).digest()).digest()

def rhash(s):
    h1 = hashlib.new('ripemd160')
    h1.update(hashlib.sha256(s).digest())
    return h1.digest()

def base58_encode(n):
    l = []
    while n > 0:
        n, r = divmod(n, 58)
        l.insert(0, b58_digits[r])
    return ''.join(l)

def base58_encode_padded(s):
    res = base58_encode(int('0x' + hexify(s), 16))
    pad = 0
    for c in s:
        if c == 0:
            pad += 1
        else:
            break
    return b58_digits[0] * pad + res

def base58_check_encode(s, version=0):
    vs = bytes([version]) + s
    check = dhash(vs)[:4]
    return base58_encode_padded(vs + check)

def get_der_field(i, binary):
    if (binary[i] == 2):
        length = binary[i+1]
        end = i + length + 2
        string = binary[i+2:end]
        return string
    else:
        return None

def der_decode(hexstring):
    binary = unhexify(hexstring)
    full_length = binary[1]
    if ((full_length + 3) == len(binary)):
        r = get_der_field(2, binary)
        s = get_der_field(len(r)+4, binary)
        return r, s
    else:
        return None

def show_results(privkeys):
    print("Possible Candidates...")
    for privkey in privkeys:
        hexprivkey = inttohexstr(privkey)
        print("intPrivkey = %d"  % privkey)
        print("hexPrivkey = %s" % hexprivkey)
        print("bitcoin Privkey (WIF) = %s" % base58_check_encode(unhexify(hexprivkey), version=128))
        print("bitcoin Privkey (WIF compressed) = %s" % base58_check_encode(unhexify(hexprivkey + "01"), version=128))

def show_params(params):
    for param in params:
        try:
            print("%s: %s" % (param, inttohexstr(params[param])))
        except:
            print("%s: %s" % (param, params[param]))

def inverse_mult(a, b, p):
    y = (a * pow(b, p-2, p))
    return y

def derivate_privkey(p, r, s1, s2, z1, z2):
    privkeys = []
    privkeys.append((inverse_mult(((z1*s2) - (z2*s1)), (r*(s1-s2)), p) % int(p)))
    privkeys.append((inverse_mult(((z1*s2) - (z2*s1)), (r*(s1+s2)), p) % int(p)))
    privkeys.append((inverse_mult(((z1*s2) - (z2*s1)), (r*(-s1-s2)), p) % int(p)))
    privkeys.append((inverse_mult(((z1*s2) - (z2*s1)), (r*(-s1+s2)), p) % int(p)))
    privkeys.append((inverse_mult(((z1*s2) + (z2*s1)), (r*(s1-s2)), p) % int(p)))
    privkeys.append((inverse_mult(((z1*s2) + (z2*s1)), (r*(s1+s2)), p) % int(p)))
    privkeys.append((inverse_mult(((z1*s2) + (z2*s1)), (r*(-s1-s2)), p) % int(p)))
    privkeys.append((inverse_mult(((z1*s2) + (z2*s1)), (r*(-s1+s2)), p) % int(p)))
    privkeys.append((inverse_mult(((z1*s2) + (z2*s1)), (r*(-s1+s2)*2), p) % int(p)))
    privkeys.append((inverse_mult(((z1*s2) - (z2*s1)), (r*(s1-s2)*3), p) % int(p)))
    privkeys.append((inverse_mult(((z1*s2) + (z2*s1)), (r*(-s1+s2)*4), p) % int(p)))
    privkeys.append((inverse_mult(((z1*s2) - (z2*s1)), (r*(s1-s2)*5), p) % int(p)))
    return privkeys

def process_signatures(params):
    p = params['p']
    r = int(input("Enter the value of r: "), 16)
    s1 = int(input("Enter the value of s1: "), 16)
    s2 = int(input("Enter the value of s2: "), 16)
    z1 = int(input("Enter the value of z1: "), 16)
    z2 = int(input("Enter the value of z2: "), 16)

    privkeys = derivate_privkey(p, r, s1, s2, z1, z2)
    num_candidates = len(privkeys)
    print("Liczba potencjalnych kandydatów:", num_candidates)
    return privkeys

def main():
    show_params(params)
    privkey = process_signatures(params)
    if len(privkey) > 0:
        show_results(privkey)

if __name__ == "__main__":
    main()
