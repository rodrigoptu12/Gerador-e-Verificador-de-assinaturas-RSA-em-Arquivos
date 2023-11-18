

import base64


with open('a.enc', 'rb') as f:
    message = f.read()
    print(base64.b64encode(message).decode('utf-8'))
