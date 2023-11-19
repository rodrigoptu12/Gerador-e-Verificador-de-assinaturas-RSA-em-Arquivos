import base64
import os
import random

# Escolha de forma aleatória dois números primos grandes p e q, da ordem de 10^{100} no mínimo.


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

# Calcule a função Função totiente de Euler em  n: phi(n) = (p-1)(q-1)


def get_phi(p: int, q: int):
    return (p - 1) * (q - 1)


def GCD(a, b):
    while b != 0:
        a, b = b, a % b
    return a

# Escolha um inteiro e, tal que 1 < e < phi(n), de forma que e e phi (n) sejam relativamente primos entre si.
# Verifique se e e phi(n) são primos entre si (ou seja, têm o máximo divisor comum igual a 1)


def get_e(phi):
    # calcular gcd entre e e phi
    e = 0
    gcd = 0
    verify = 0
    while gcd != 1 or verify != 1:
        e = os2ip(os.urandom(128))
        gcd = GCD(e, phi)
        if 1 < e and e < phi:
            verify = 1
    return e

# Calcule d de forma de === 1 (mod phi(n)), ou seja, d seja o inverso multiplicativo de e em mod phi(n)
# No passo 5 é usado o algoritmo de Euclides estendido, e o conceito de inverso multiplicativo que vem da aritmética modular


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
    n, e = PublicKey
    # c = m^e mod n
    c = pow(m, e, n)
    return c


def decrypt(c: int, PrivateKey: tuple[int, int]):
    n, d = PrivateKey
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
    PublicKey = (n, e)
    PrivateKey = (n, d)
    return PublicKey, PrivateKey


if __name__ == '__main__':

    p, q = get_pand_Q()

    n = get_n(p, q)

    phi = get_phi(p, q)
    e = get_e(phi)
    d = get_d(e, phi)
    # Chave pública: (n, e)
    PublicKey = (n, e)
    print("Chave pública: ", PublicKey)
    # Chave privada: (n, d)
    PrivateKey = (n, d)
    print("Chave privada: ", PrivateKey)

    message = "Ola mundo so estou testando tudo isso e o tamanho 000000000000000000000000000000000000000 se acredita?"
    message = message.encode()
    message = base64.b64encode(message)
    print(message)
    message = os2ip(message)

    print("Message: ", message)
    print("")

    c = encrypt(message, PublicKey)
    print("Message Cifrada: ", c)

    message = decrypt(c, PrivateKey)
    message = i2osp(message)
    message = base64.b64decode(message)
    message = message.decode()
    print("Message Descifrada: ", message)

    # Salvar arquivo - chave pública, privada

    def salvarChave(chave, nome):
        with open(nome, 'w') as f:
            # clear file
            f.write('%d,%d' % (chave[0], chave[1]))

    salvarChave(PublicKey, 'public.key')
    salvarChave(PrivateKey, 'private.key')
