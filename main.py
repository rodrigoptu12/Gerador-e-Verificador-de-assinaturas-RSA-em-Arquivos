from argparse import ArgumentParser

import RSA_AOEP
import sign
from keys import (load_private_key, load_public_key, save_private_key,
                  save_public_key)
from RSA import generate_key_pair

parser = ArgumentParser()
parser.add_argument('-i', type=str)
parser.add_argument('-o', type=str)
parser.add_argument('-privkey', type=str)
parser.add_argument('-pubkey', type=str)
parser.add_argument('-encrypt', action='store_true')
parser.add_argument('-decrypt', action='store_true')
parser.add_argument('-sign', action='store_true', dest='sign_flag')
parser.add_argument('-verify', action='store_true')
parser.add_argument('-genkeys', action='store_true')
parser.add_argument('-signature', type=str)
args = parser.parse_args()


input_file = args.i
output_file = args.o
encrypt = args.encrypt
decrypt = args.decrypt
sign_flag = args.sign_flag
verify = args.verify
genkeys = args.genkeys
signature_file = args.signature
private_key = args.privkey
public_key = args.pubkey


if private_key:
    private_key = load_private_key(private_key)

if public_key:
    public_key = load_public_key(public_key)

if input_file:
    with open(input_file, 'rb') as f:
        data = f.read()

if genkeys:
    public_key, private_key = generate_key_pair()
    (n, e) = public_key
    (n, d, e, p, q) = private_key
    save_public_key(n, e)
    save_private_key(n, d, e, p, q)
    print('Chaves geradas com sucesso.')
elif encrypt:
    C = RSA_AOEP.RSAES_OAEP_ENCRYPT(private_key, data)
    with open(output_file, 'wb') as f:
        f.write(C)
    print('Arquivo criptografado com sucesso.')
elif decrypt:
    M = RSA_AOEP.RSAES_OAEP_DECRYPT(public_key, data)
    with open(output_file, 'wb') as f:
        f.write(M)
    print('Arquivo descriptografado com sucesso.')
elif sign_flag:
    signature = sign.sign(data, private_key)
    sign.save_signature(output_file, signature)
    print('Assinatura gerada com sucesso.')
elif verify:
    signature = open(signature_file, 'rb').read()
    if sign.verify_signature(data, signature, public_key):
        print("Assinatura válida.")
    else:
        print("Assinatura inválida.")
else:
    print('Nenhuma operação selecionada. Use -h para ajuda')
