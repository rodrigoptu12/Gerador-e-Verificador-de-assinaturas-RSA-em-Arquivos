import base64


with open('sha1.sign',  'r') as f:
    signaturehex = f.read()
    signature = bytes.fromhex(signaturehex)
    print(base64.b64encode(signature).decode())
