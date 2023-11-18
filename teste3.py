import base64

from pyasn1.codec.der import decoder
from pyasn1.type import univ, constraint, namedtype


#RSAPublicKey ::= SEQUENCE {
        #      modulus           INTEGER,  -- n
        #      publicExponent    INTEGER   -- e
        #  }

class RSAPublicKey(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('modulus', univ.Integer()),
        namedtype.NamedType('publicExponent', univ.Integer())
    )

def parse_asn1_key(asn1_key):
    decoded_key, _ = decoder.decode(asn1_key, asn1Spec=RSAPublicKey())
    modulus = int(decoded_key['modulus'])
    public_exponent = int(decoded_key['publicExponent'])
    return modulus, public_exponent

public_key = """-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCI+AQnx67vUUGghT/xK+L8Z0K9
KY1dbcehJod+YVaIfng1Kf3jq3xJz9nq37h9HmUOszURuXYk27jbewWUV+azWpBv
uhApZfFHVmB03U0FeZ0vnEO+MFdVvYaDg8CgGfGhv/uU8sYlbOR/XwnNY37Iayhw
IWfeKG0dyvF5wrubfwIDAQAB
-----END PUBLIC KEY-----"""

# Remover cabeçalhos e rodapés

asn1_string = public_key.replace("-----BEGIN PUBLIC KEY-----", "")
asn1_string = asn1_string.replace("-----END PUBLIC KEY-----", "")
asn1_string = asn1_string.replace("\n", "")
asn1_string = base64.b64decode(asn1_string)



# Chamar a função para obter os valores de "n" e "e"
modulus, public_exponent = parse_asn1_key(asn1_string)

# Exibir os valores recuperados
# print("Modulus (n):", modulus)
# print("Public Exponent (e):", public_exponent)
