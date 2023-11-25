from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

def read_pkcs8_private_key_second_approach(file_path):
    with open(file_path, 'rb') as file:
        key_data = file.read()

        key_info = serialization.load_pem_private_key(
            key_data,
            password=None,  # Se a chave estiver protegida por senha, forneça a senha aqui
            backend=default_backend()
        )

        return key_info

# Exemplo de uso:
file_path = '../private.pem'
private_key = read_pkcs8_private_key_second_approach(file_path)

#  extrair parametros n e d da chave privada
n = private_key.private_numbers().public_numbers.n
e = private_key.private_numbers().public_numbers.e
d = private_key.private_numbers().d


print("n:", n)
print("d:", d)
