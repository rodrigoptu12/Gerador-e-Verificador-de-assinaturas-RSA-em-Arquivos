import os
import base64
import random
# Escolha de forma aleatória dois números primos grandes p e q, da ordem de 10^{100} no mínimo.

def is_prime(n, k=5):
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


def GetPrime():
    while True:
        p = int.from_bytes(os.urandom(128), byteorder='big')
        if is_prime(p):
            return p
    
def GetPandQ():    
    p = GetPrime()
    q = GetPrime()
    return p, q

def GetN(p, q):
    return p * q

# Calcule a função Função totiente de Euler em  n: phi(n) = (p-1)(q-1)
def GetPhi(p, q):
    return (p - 1) * (q - 1)

# Escolha um inteiro e, tal que 1 < e < phi(n), de forma que e e phi (n) sejam relativamente primos entre si.
# Verifique se e e phi(n) são primos entre si (ou seja, têm o máximo divisor comum igual a 1)

def MDC(a, b):
    while b != 0:
        a, b = b, a % b
    return a


def GetE(phi):
    # calcular mdc entre e e phi
    e = 0
    mdc = 0
    verify = 0
    while mdc!= 1 or verify != 1:
        e = int.from_bytes(os.urandom(128), byteorder='big')
        mdc = MDC(e, phi)
        print("mdc = ", mdc)
        if e < phi and e > 1:
            verify = 1
    return e

# Calcule d de forma de === 1 (mod phi(n)), ou seja, d seja o inverso multiplicativo de e em mod phi(n)
# No passo 5 é usado o algoritmo de Euclides estendido, e o conceito de inverso multiplicativo que vem da aritmética modular
def GetD(e, phi):
    d, x, _ = extended_gcd(e, phi)
    if d == 1:
        return x % phi
    else:
        raise ValueError("O inverso multiplicativo não existe para os valores fornecidos")

def extended_gcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        d, x, y = extended_gcd(b % a, a)
        return (d, y - (b // a) * x, x)


def Criptografa(mensagem, PublicKey):
 
    n, e = PublicKey
    # C = M^e mod n
    C = pow(mensagem, e, n)
    return C

def Descriptografa(C, PrivateKey):
    n, d = PrivateKey
    # M = C^d mod n
    M = pow(C, d, n)
    return M


print("Gerando p e q...")
p, q = GetPandQ()
# p = 43
# q = 59
print("p = ", p)    
print("q = ", q)

print("Gerando n...")
n = GetN(p, q)
print("n = ", n)

print("Gerando phi...")
phi = GetPhi(p, q)
print("phi = ", phi)

print("Gerando e...")
e = GetE(phi)
# e = 11
print("e = ", e)

print("Gerando d...")
d = GetD(e, phi)
print("d = ", d)

# Chave pública: (n, e)
PublicKey = (n, e)
print("Chave pública: ", PublicKey)

# Chave privada: (n, d)
PrivateKey = (n, d)
print("Chave privada: ", PrivateKey)


mensagem = "Ola mundo so estou testando tudo isso e o tamanho 000000000000000000000000000000000000000 se acredita?"
mensagem = mensagem.encode('utf-8')
mensagem = base64.b64encode(mensagem)
mensagem = int.from_bytes(mensagem, byteorder='big')

print ("Mensagem: ", mensagem)
print("")
C = Criptografa(mensagem, PublicKey)
print("Mensagem Cifrada: ", C)

mensagem = Descriptografa(C, PrivateKey)
mensagem = mensagem.to_bytes((mensagem.bit_length() + 7) // 8, byteorder='big')
mensagem = base64.b64decode(mensagem)
mensagem = mensagem.decode('utf-8')
print("Mensagem Descifrada: ", mensagem)




