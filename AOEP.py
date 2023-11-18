import base64
import hashlib
import os

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

# def xor_bytes(palavra, palavra2):
#     aux = []
#     for i in range(len(palavra)):
#         aux += [palavra[i] ^ palavra2[i]]
#     return bytes(aux)


def oaep_pad(message, seed_length=512, hash_func=hashlib.sha256):
    # Parâmetros padrão: seed_length = tamanho da semente para MGF1, hash_func = função de haFsh


    # Etapa 1: Converte a mensagem em um inteiro
    m_int = int.from_bytes(message.encode('utf-8'), 'big')

    # Etapa 2: Gera a semente aleatória
    seed = os.urandom(seed_length)

    # Etapa 3: Aplica MGF1 para gerar a máscara
    mask = mgf1(seed, len(message), hash_func)

    # Etapa 4: Realiza o XOR entre a mensagem e a máscara
    masked_msg = xor_bytes(message.encode('utf-8'), mask)

    # Etapa 5: Aplica MGF1 para gerar a semente invertida
    inv_mask = mgf1(masked_msg, seed_length, hash_func)

    # Etapa 6: Realiza o XOR entre a semente original e a semente invertida
    masked_seed = xor_bytes(seed, inv_mask)

    # Etapa 7: Retorna a mensagem cifrada (masked_seed || masked_msg)
    return masked_seed + masked_msg

def oaep_unpad(ciphertext, seed_length=512, hash_func=hashlib.sha256):
    # Etapa 1: Divide a mensagem cifrada em semente e mensagem
    masked_seed = ciphertext[:seed_length]
    masked_msg = ciphertext[seed_length:]

    # Etapa 2: Aplica MGF1 para gerar a semente invertida
    inv_mask = mgf1(masked_msg, seed_length, hash_func)

    # Etapa 3: Realiza o XOR entre a semente original e a semente invertida
    seed = xor_bytes(masked_seed, inv_mask)

    # Etapa 4: Aplica MGF1 para gerar a máscara
    mask = mgf1(seed, len(masked_msg), hash_func)

    # Etapa 5: Realiza o XOR entre a mensagem cifrada e a máscara
    original_msg = xor_bytes(masked_msg, mask)

    # Etapa 6: Converte a mensagem para string
    return original_msg.decode('utf-8')

# Exemplo de uso:
message = "Hello"
message=message.encode().hex()
# Cifrar
ciphertext = oaep_pad(message)
ciphertext_hex=ciphertext.hex()

print("Mensagem Cifrada:", ciphertext_hex)

# Decifrar
decrypted_message = oaep_unpad(ciphertext)
decrypted_message=bytes.fromhex(decrypted_message).decode()

print("Mensagem Decifrada:", decrypted_message)
