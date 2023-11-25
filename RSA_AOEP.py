import hashlib
import os
from RSA import decrypt, encrypt, i2osp, os2ip


def mgf1(mgf_seed: bytes, mask_len: int, hash=hashlib.sha1) -> bytes:
    hLen = hash().digest_size
    if mask_len > (hLen << 32):
        raise ValueError("mask too long")
    T = b""
    counter = 0
    while len(T) < mask_len:
        C = i2osp(counter, 4)
        T += hash(mgf_seed + C).digest()
        counter += 1
    return T[:mask_len]


def xor(x, y):
    return bytes(a ^ b for a, b in zip(x, y))


def RSAES_OAEP_ENCRYPT(K: tuple[int, int], M: bytes, hash=hashlib.sha1, MGF=mgf1, L=''):
    n = K[0]
    h_len = hash().digest_size
    _2h_len = 2 * h_len
    k = (n.bit_length() + 7) // 8
    m_len = len(M)
    print(k - _2h_len - 2)
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

    c = encrypt(m, K)

    C = i2osp(c)

    return C


def RSAES_OAEP_DECRYPT(K: tuple[int, int], C: bytes, hash=hashlib.sha1, MGF=mgf1, L=''):
    n = K[0]
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
