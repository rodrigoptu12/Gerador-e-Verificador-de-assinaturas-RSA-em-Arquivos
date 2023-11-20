import base64
import hashlib
import os

from load_keys import load_public_key, load_private_key
from RSA import decrypt, encrypt, generate_key_pair, i2osp, os2ip


def mgf1(mgf_seed: bytes, mask_len: int, hash=hashlib.sha1) -> bytes:
    """Mask generation function."""
    hLen = hash().digest_size
    # https://www.ietf.org/rfc/rfc2437.txt
    # 1. If l > 2^32(hLen), output "mask too long" and stop.
    if mask_len > (hLen << 32):
        raise ValueError("mask too long")
    # 2. Let T be the empty octet string.
    T = b""
    # 3. For counter from 0 to \lceil{l / hLen}\rceil-1, do the following:
    # Note: \lceil{l / hLen}\rceil-1 is the number of iterations needed,
    #       but it's easier to check if we have reached the desired length.
    counter = 0
    while len(T) < mask_len:
        # a. Convert counter to an octet string C of length 4 with the primitive I2OSP: C = I2OSP (counter, 4)
        C = i2osp(counter, 4)
        # b. Concatenate the hash of the mgf_seed Z and C to the octet string T: T = T || Hash (Z || C)
        T += hash(mgf_seed + C).digest()
        counter += 1
    # 4. Output the leading l octets of T as the octet string mask.
    return T[:mask_len]


def xor(x, y):
    return bytes(a ^ b for a, b in zip(x, y))


def RSAES_OAEP_ENCRYPT(P_key: tuple[int, int], M: bytes, hash, MGF, L=''):
    (n, e) = P_key
    h_len = hash().digest_size
    _2h_len = 2 * h_len
    k = (n.bit_length() + 7) // 8
    m_len = len(M)

    if m_len > (k - _2h_len - 2):
        raise ValueError("message too long")

    l_hash = hash(L.encode()).digest()

    PS = b'\x00' * (k - m_len - _2h_len - 2)

    DB = l_hash + PS + b'\x01' + M

    seed = os.urandom(h_len)

    db_mask = MGF(seed, k - h_len - 1, hash)

    masked_db = xor(DB, db_mask)

    seed_mask = MGF(masked_db, h_len, hash)

    masked_seed = xor(seed, seed_mask)

    EM = b'\x00' + masked_seed + masked_db

    m = os2ip(EM)

    c = encrypt(m, P_key)

    C = i2osp(c)

    return C


def RSAES_OAEP_DECRYPT(K: tuple[int, int], C: bytes, hash, MGF, L=''):
    (n, d) = K
    h_len = hash().digest_size
    _2h_len = 2 * h_len
    k = (n.bit_length() + 7) // 8

    if len(C) != k or k < _2h_len + 2:
        raise ValueError("decryption error")

    c = os2ip(C)

    m = decrypt(c, K)

    EM = i2osp(m, k)

    l_hash = hash(L.encode()).digest()

    Y = EM[0]

    masked_seed = EM[1:h_len + 1]

    masked_db = EM[h_len + 1:]

    seed_mask = MGF(masked_db, h_len, hash)

    seed = xor(masked_seed, seed_mask)

    db_mask = MGF(seed, k - h_len - 1, hash)

    DB = xor(masked_db, db_mask)

    l_hash_ = DB[:h_len]

    i = h_len
    while i < len(DB) and DB[i] == 0:
        i += 1

    if Y != 0 or l_hash != l_hash_ or i == len(DB) or DB[i] != 1:
        raise ValueError("decryption error")

    M = DB[i + 1:]

    return M


if __name__ == '__main__':

    with open('plaintext.txt', 'r') as f:
        message = f.read().encode()

        # public_key = load_public_key('public_key.pem')
        # private_key = load_private_key('private_key.pem')
        public_key, private_key = generate_key_pair()

        n, e = public_key
        n, d = private_key

        print(n)
        print('\n')
        print(e)
        print('\n')
        print(d)
        print('\n')


        C = RSAES_OAEP_ENCRYPT((n, e), message, hashlib.sha1, mgf1)
        print(base64.b64encode(C))
        M = RSAES_OAEP_DECRYPT((n, d), C, hashlib.sha1, mgf1)
        m = M.decode()
        print(m)
