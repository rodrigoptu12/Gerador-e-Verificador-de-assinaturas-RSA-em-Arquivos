from argparse import ArgumentParser

import RSA_AOEP
import sign
from keys import (load_private_key, load_public_key, save_private_key,
                  save_public_key)
from RSA import generate_key_pair

parser = ArgumentParser()
parser.add_argument('-i', type=str, default='input.txt')
parser.add_argument('-o', type=str, default='out.txt')
parser.add_argument('-privkey', type=str)
parser.add_argument('-pubkey', type=str)
parser.add_argument(
    '-encrypt', action='store_true', dest='encrypt_flag')
parser.add_argument(
    '-decrypt', action='store_true', dest='decrypt_flag')
parser.add_argument(
    '-sign', action='store_true', dest='sign_flag')
parser.add_argument(
    '-verify', action='store_true', dest='verify_flag')
parser.add_argument(
    '-genkeys', action='store_true', dest='genkeys')
parser.add_argument('-signature', type=str, default='input.sign')
args = parser.parse_args()


input_file = args.i
output_file = args.o
encrypt_flag = args.encrypt_flag
decrypt_flag = args.decrypt_flag
sign_flag = args.sign_flag
verify_flag = args.verify_flag
genkeys_flag = args.genkeys
signature_file = args.signature
private_key = args.privkey
public_key = args.pubkey

# python main.py -genkeys
# python main.py -i input.txt -o output.rsa -encrypt -privkey private_key.pem
# python main.py -i output.rsa -o output.txt -decrypt -pubkey public_key.pem
# python main.py -i input.txt -o input.sign -sign -privkey private_key.pem
# python main.py -i input.txt -signature input.sign -verify -pubkey public_key.pem
if private_key:
    private_key = load_private_key(private_key)

if public_key:
    public_key = load_public_key(public_key)

if genkeys_flag:
    public_key, private_key = generate_key_pair()
    (n, e) = public_key
    (n, d, e, p, q) = private_key
    save_public_key(n, e)
    save_private_key(n, d, e, p, q)
else:
    f = open(input_file, 'rb')
    data = f.read()

    if encrypt_flag:
        C = RSA_AOEP.RSAES_OAEP_ENCRYPT(private_key, data)
        with open(output_file, 'wb') as f:
            f.write(C)

    elif decrypt_flag:
        M = RSA_AOEP.RSAES_OAEP_DECRYPT(public_key, data)
        with open(output_file, 'wb') as f:
            f.write(M)
    elif sign_flag:
        signature = sign.sign(data, private_key)
        sign.save_signature(output_file, signature)
    elif verify_flag:
        signature = open(signature_file, 'rb').read()
        if sign.verify_signature(data, signature, public_key):
            print("Assinatura válida")
        else:
            print("Assinatura inválida")

    else:
        print('Please check your command')

    f.close()
