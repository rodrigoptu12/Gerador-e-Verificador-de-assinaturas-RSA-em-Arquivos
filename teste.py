from Crypto.Util import number
 p = number.getPrime(1024)
    q = number.getPrime(1024)
    return p, q

def GetN(p, q):
    return p * q

def GetE(p, q):
    phi = (p - 1) * (q - 1)
    e = number.getPrime(1024)
    while number.GCD(e, phi) != 1:
        e = number.getPrime(1024)
    return e