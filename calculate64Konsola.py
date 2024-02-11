import random
from src.conversion_utils import convert_hex_to_wif
from src.common import process_file

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

# Input values for R, S, and Z from the console
R = int(input("Enter the value for R: "), 16)
S = int(input("Enter the value for S: "), 16)
Z = int(input("Enter the value for Z: "), 16)

with open("daten.txt", "w") as file:
    for _ in range(10000):
       # K = 0x070239C013E8F40C8C2A0E608AE15A6B23D4A09295BE678B21A5F1DCEAE1F634
        K = random.randint(730750818665451459101842416358141509827966271488, 1461501637330902918203684832716283019655932542975)
        #K = random.randint(1, 5000)
        result = h((((S * K) - Z) * modinv(R, N)) % N)
        if len(result) == 64:
            file.write(result + "\n")

# Function to convert hex private key to WIF and write to file
def convert(hex_private_key):
    wif = convert_hex_to_wif(hex_private_key, compressed=False)
    with open('list-WIF-uncompressed.txt', 'a', encoding='utf-8') as file:
        file.write(f"{wif}\n")

# Call common.py to process the file
process_file("daten.txt", convert)

print("Conversion successful.")

