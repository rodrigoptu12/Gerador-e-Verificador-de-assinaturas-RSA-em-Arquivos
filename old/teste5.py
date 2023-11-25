import rsa

# Caminho para o arquivo que contém a chave privada
caminho_arquivo_chave_privada = '../private.pem'

# Lê o conteúdo do arquivo
with open(caminho_arquivo_chave_privada, 'rb') as arquivo:
    r = arquivo.read()
    private_key = rsa.key.AbstractKey.load_pkcs1(r, format='PEM')
    print(private_key)
# Agora você tem a chave privada pronta para uso
print("Chave privada lida com sucesso!")
