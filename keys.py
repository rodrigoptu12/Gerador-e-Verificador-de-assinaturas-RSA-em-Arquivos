from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import rsa

def load_public_key(file_path):
    with open(file_path, 'r') as f:
        public_key_pem = f.read()
        if "RSA" in public_key_pem:
            public_key = rsa.PublicKey.load_pkcs1(public_key_pem.encode())
        else:
            public_key = rsa.PublicKey.load_pkcs1_openssl_pem(
                public_key_pem.encode())
        return (public_key.n, public_key.e)


def load_private_key(file_path):
    with open(file_path, 'rb') as file:
        key_data = file.read()

        key_info = serialization.load_pem_private_key(
            key_data,
            password=None,
            backend=default_backend()
        )
        n = key_info.private_numbers().public_numbers.n
        e = key_info.private_numbers().public_numbers.e
        d = key_info.private_numbers().d
        p = key_info.private_numbers().p
        q = key_info.private_numbers().q
        private_key = (n, d, e, p, q)
        return private_key


def save_private_key(n, d, e, p, q):
    private_key = rsa.PrivateKey(n, e, d, p, q)
    private_key_pem = private_key.save_pkcs1()

    with open("private_key.pem", "wb") as f:
        f.write(private_key_pem)


def save_public_key(n, e):
    public_key = rsa.PublicKey(n, e)
    public_key_pem = public_key.save_pkcs1()

    with open("public_key.pem", "wb") as f:
        f.write(public_key_pem)
