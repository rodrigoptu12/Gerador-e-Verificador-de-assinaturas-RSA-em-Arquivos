import os
import random


def i2osp(x: int, x_len: int = None):
    if x_len is None:
        x_len = (x.bit_length() + 7) // 8
    return x.to_bytes(x_len)


def os2ip(X):
    return int.from_bytes(X)


def is_prime(n: int, k=128):
    """Testa se n é provavelmente primo usando o teste de Miller-Rabin."""
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2

    for _ in range(k):
        a = random.randint(2, n - 1)
        x = pow(a, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def get_prime():
    while True:
        p = os2ip(os.urandom(128))  # 128 bytes = 1024 bits
        if is_prime(p):
            return p


def get_pand_Q():
    p = get_prime()
    q = get_prime()
    return p, q


def get_n(p: int, q: int):
    return p * q


def get_phi(p: int, q: int):
    return (p - 1) * (q - 1)


def GCD(a, b):
    while b != 0:
        a, b = b, a % b
    return a


def get_e(phi):
    e = 0
    gcd = 0
    verify = 0
    while gcd != 1 or verify != 1:
        e = os2ip(os.urandom(128))
        gcd = GCD(e, phi)
        if 1 < e and e < phi:
            verify = 1
    return e


def get_d(e: int, phi: int):
    d, x, _ = extended_gcd(e, phi)
    if d == 1:
        return x % phi

    raise ValueError(
        "O inverso multiplicativo não existe para os valores fornecidos")


def extended_gcd(a: int, b: int):
    if a == 0:
        return (b, 0, 1)
    else:
        d, x, y = extended_gcd(b % a, a)
        return (d, y - (b // a) * x, x)


def encrypt(m: int, PublicKey: tuple[int, int]):
    n = PublicKey[0]
    e = PublicKey[1]
    # c = m^e mod n
    c = pow(m, e, n)
    return c


def decrypt(c: int, PrivateKey: tuple[int, int]):
    n = PrivateKey[0]
    d = PrivateKey[1]
    # m = m^d mod n
    m = pow(c, d, n)
    return m


def generate_key_pair():
    p = get_prime()
    q = get_prime()
    n = get_n(p, q)
    phi = get_phi(p, q)
    e = get_e(phi)
    d = get_d(e, phi)
    public_key = (n, e)
    private_key = (n, e, d, p, q)
    return public_key, private_key
