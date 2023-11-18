import rsa

def load_public_key(filename):
    with open(filename, 'rb') as f:
        public_key_pem = f.read()
        public_key = rsa.PublicKey.load_pkcs1_openssl_pem(public_key_pem)
        return public_key

def load_private_key(filename):
    with open(filename, 'rb') as f:
        private_key_pem = f.read()
        private_key = rsa.PrivateKey.load_pkcs1_openssl_pem(private_key_pem)
        return private_key
