from hashlib import sha3_256

from RSA_AOEP import RSAES_OAEP_DECRYPT, RSAES_OAEP_ENCRYPT


def sign(M: bytes, private_key: tuple[int, int]) -> bytes:
    message_hash = sha3_256(M).digest()
    signature = RSAES_OAEP_ENCRYPT(private_key, message_hash)
    return signature


def verify_signature(M: bytes, signature: bytes, public_key: tuple[int, int]) -> bool:
    message_hash = sha3_256(M).digest()
    decoded_signature = RSAES_OAEP_DECRYPT(public_key, signature)
    return decoded_signature == message_hash


def save_signature(filename, signature: bytes):
    with open(filename, "wb") as f:
        f.write(signature)
