1. **Geração das Chaves RSA:**
   - Gere dois números primos grandes \(p\) e \(q\).
   - Calcule \(n = p \times q\).
   - Calcule \(\phi(n) = (p-1) \times (q-1)\).
   - Escolha um expoente público \(e\) que seja relativamente primo a \(\phi(n)\).
   - Calcule o expoente privado \(d\) como o inverso multiplicativo de \(e\) em \(\mod \phi(n)\).
   - A chave pública é \((n, e)\) e a chave privada é \((n, d)\).

2. **Cifragem (Usando RSA + OAEP):**
   - Antes de cifrar, aplique o enchimento OAEP à mensagem original.
   - Converta a mensagem enchida em um número inteiro.
   - Cifre o número usando a chave pública RSA: \(C = M^e \mod n\).

3. **Envio da Mensagem Cifrada:**
   - Envie o valor cifrado \(C\) para o destinatário.

4. **Decifragem (Usando RSA + OAEP):**
   - O destinatário recebe \(C\) e aplica a operação de decifragem RSA: \(M = C^d \mod n\).
   - Converta o número decifrado de volta para a representação da mensagem enchida.

5. **Remoção do OAEP:**
   - Remova o enchimento OAEP da mensagem decifrada para obter a mensagem original.
