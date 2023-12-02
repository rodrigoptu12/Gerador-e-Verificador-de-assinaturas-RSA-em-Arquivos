# Documentação do Script

## Descrição

Este script Python oferece funcionalidades relacionadas à criptografia RSA-AOEP, incluindo geração de chaves, criptografia, descriptografia, assinatura e verificação de assinatura.

## Uso

O script pode ser utilizado com diferentes opções, conforme as seguintes instruções:

### Opções disponíveis

-   **-i**: Especifica o arquivo de entrada.
-   **-o**: Especifica o arquivo de saída.
-   **-privkey**: Especifica o caminho para o arquivo contendo a chave privada.
-   **-pubkey**: Especifica o caminho para o arquivo contendo a chave pública.
-   **-encrypt**: Habilita a operação de criptografia.
-   **-decrypt**: Habilita a operação de descriptografia.
-   **-sign**: Habilita a operação de assinatura.
-   **-verify**: Habilita a operação de verificação de assinatura.
-   **-genkeys**: Habilita a geração de um par de chaves.
-   **-signature**: Especifica o arquivo contendo a assinatura.

### Exemplos de Uso

1. **Geração de Chave:**

    ```bash
    python main.py -genkeys
    ```

2. **Criptografia:**

    ```bash
    python main.py -encrypt -i input.txt -o output.rsa -privkey private_key.pem
    ```

3. **Descriptografia:**

    ```bash
    python main.py -decrypt -i output.rsa -o output.txt -pubkey public_key.pem
    ```

4. **Assinatura:**

    ```bash
    python main.py -sign -i input.txt -o input.sign -privkey private_key.pem
    ```

5. **Verificação de Assinatura:**
    ```bash
    python main.py -verify -i input.txt -signature input.sign -pubkey public_key.pem
    ```

## Dependências

    pip install rsa
    pip install cryptography
