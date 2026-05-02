from Crypto.Random.random import randint
from math import gcd
from Crypto.Util.number import inverse
import hashlib


def hash_vault(vault_data: str) -> int:
    h = hashlib.sha256(vault_data.encode()).hexdigest()
    return int(h, 16)


def sign(vault_hash, x, q, alpha):
    while True:
        k = randint(2, q - 2)
        if gcd(k, q - 1) == 1:
            r = pow(alpha, k, q)
            k_inverse = inverse(k, q - 1)
            s = ((vault_hash - x * r) * k_inverse) % (q - 1)
            if s != 0:
                break

    return r, s


def verify(r, s, vault_hash, y, alpha, q):
    if not (1 <= r <= q - 1) or not (1 <= s <= q - 2):
        return False
    left = pow(alpha, vault_hash, q)
    right = (pow(y, r, q) * pow(r, s, q)) % q
    return left == right
