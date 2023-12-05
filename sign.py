import base64
from hashlib import sha3_256
from typing import Tuple

from RSA_AOEP import RSAES_OAEP_DECRYPT, RSAES_OAEP_ENCRYPT


def sign(M: bytes, private_key: Tuple[int, int]) -> bytes:
    message_hash = sha3_256(M).digest()
    signature = RSAES_OAEP_ENCRYPT(private_key, message_hash)
    signature = base64.b64encode(signature)
    return signature


def verify_signature(M: bytes, signature: bytes, public_key: Tuple[int, int]) -> bool:
    message_hash = sha3_256(M).digest()
    signature = base64.b64decode(signature)
    decoded_signature = RSAES_OAEP_DECRYPT(public_key, signature)
    return decoded_signature == message_hash


def save_signature(filename, signature: bytes):
    with open(filename, "w") as f:
        f.write(signature.decode())
