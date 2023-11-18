import base64
import hashlib
import os
from RSA import Criptografa, generate_key_pair
from load_keys import load_public_key

def mgf1(seed: bytes, length: int, hash_func) -> bytes:
    """Mask generation function."""
    hLen = hash_func().digest_size
    # https://www.ietf.org/rfc/rfc2437.txt
    # 1. If l > 2^32(hLen), output "mask too long" and stop.
    if length > (hLen << 32):
        raise ValueError("mask too long")
    # 2. Let T be the empty octet string.
    T = b""
    # 3. For counter from 0 to \lceil{l / hLen}\rceil-1, do the following:
    # Note: \lceil{l / hLen}\rceil-1 is the number of iterations needed,
    #       but it's easier to check if we have reached the desired length.
    counter = 0
    while len(T) < length:
        # a. Convert counter to an octet string C of length 4 with the primitive I2OSP: C = I2OSP (counter, 4)
        C = int.to_bytes(counter, 4, "big")
        # b. Concatenate the hash of the seed Z and C to the octet string T: T = T || Hash (Z || C)
        T += hash_func(seed + C).digest()
        counter += 1
    # 4. Output the leading l octets of T as the octet string mask.
    return T[:length]


def xor_bytes(b1, b2):
    # Função para realizar XOR entre dois bytes
    return bytes([_a ^ _b for _a, _b in zip(b1, b2)])

def RSAES_OAEP_ENCRYPT(P_key, M, MGF, hash_func, L=''):
    (n, e) = P_key
    h_len = hash_func().digest_size
    _2H_len = 2 * h_len
    k = (n.bit_length() + 7) // 8
    m_len = len(M)

    if m_len > (n.bit_length() - _2H_len - 2):
        raise ValueError("message too long")

    if len(L) > h_len:
        raise ValueError("label too long")

    l_hash = hash_func(L.encode()).digest()

    PS = b'\x00' * (k - m_len - _2H_len - 2)

    DB = l_hash + PS + b'\x01' + M

    seed = os.urandom(h_len)

    db_mask = MGF(seed, k - h_len - 1, hash_func)

    masked_db = xor_bytes(DB, db_mask)

    seed_mask = MGF(masked_db, h_len, hash_func)

    masked_seed = xor_bytes(seed, seed_mask)

    EM = b'\x00' + masked_seed + masked_db

    m = int.from_bytes(EM, 'big')

    c = Criptografa(m, P_key)

    C = c.to_bytes((c.bit_length() + 7) // 8, byteorder='big')

    return C


if __name__ == '__main__':

    with open('plaintext.txt', 'r') as f:
        message = f.read()
        message = message.encode('utf-8')

        public_key = load_public_key('public_key.pem')
        n = public_key.n
        e = public_key.e

        def bytes_to_hex_string(bytes: bytes):
            return ''.join(list(map(lambda x: f'{x:0>2x}', bytes)))

        C = RSAES_OAEP_ENCRYPT((n,e), message, mgf1, hashlib.sha1)


        print(base64.b64encode(C).decode('utf-8'))
