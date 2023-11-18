from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

def load_private_key_pem(pem_data, password=None):
    private_key = serialization.load_pem_private_key(
        pem_data.encode('utf-8'),
        password=password,
        backend=default_backend()
    )
    private_numbers = private_key.private_numbers()
    return (
        private_numbers.public_numbers.n,
        private_numbers.public_numbers.e,
        private_numbers.d,
        private_numbers.p,
        private_numbers.q
    )

# Exemplo de uso:
private_key_pem = """
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDqoI1AesZhdNUt
gjaySb9ZiRYUJt+/uKDbDWSRMXJzysAIodExCcWZd0EbJJoYnnNe+kTC+H8X4OWE
5CYbSsQbjapknKrLY6a+6iTKHKJD/CvGR2woyn/1g/jJ5Q6s22NTWLyX8pw0ZD08
Vz0FBuh9GmwZrI4WxxKhM4H3LWtw1et5u3XPsEU2sz/LiDr2XwKn5yAiT34+WPHz
RK4dxCyFjd5/fJ5rn2SWPYpGrDdGs+MWo1LQ5GazIvawqnipjrupphZ1kdSRgjBe
1utKLvfyftUJX9VXZ5961Fd0SD12UCbkou3LWvpuH6ePcuVJAQ1VEhvgl/yzACJa
4VqYpJKDAgMBAAECggEAF+Agn5geydoGu2vNvxTMGQNfMMvH5w2VqNTTEAdVGz1d
j0NQM0pIRlahVG7EE49END0JdEGvRTHIiV5iFlLkY91lonli0/GfDTxsY/jH9l0Z
40JvWjNJFCXK0lixxptInzmfb2LrzFUK+jHybqmGTPy8VVx+1QiK98ZzCkEf9spM
FMhb49W+V6FP/O9WvHbTXFo8IIqGEDzOMRbHSRq8IyvTDeHQ/jr9soGXLxyAmlxz
8oob+Ts8kiffEaOW3CVRjn7h4j6DogpEJD0IhEZS0iovOzejVJrumfzfYIW2by5y
PPR+O7zAE5dV9SRTdWUgf8UEFLI/0U40jc921tv7mQKBgQD9bD9ZrNZLldLVX4wd
lvl4whXHXeYiDpeGPGLoz6zJY4kol+JnUQJMoCnhgeSkgRqrN+ld7tzL4I0zWOtF
PGaOMTjOHogDRsJdkTxi2/HF+Jghuc8hcn5B326yCKf/oIaSKAMq8YxuVJaUosya
Lpt1PacklBeCtIjn0NjucB+pFwKBgQDtA19LTkfeeYssfqqh96eR/Y5h1caT7tlR
sT2AD2fCaXUPM/8jaOw/3TrJfEeG1sFSAvYM3IhIvLAMmmYpzTF6hPZig8gkkc6E
vm8qXyjFF9etE6YZ9GjgvRUPC4p6X/H8Z00RufJUqAyG3zQR/p7ynGhStVKpYU9t
XMZB667tdQKBgQD1vEptrWAa6QwI5V6brrL3utOdf9rQ+W9KtjF+6Sn2GnN8jlL2
tiHRpZkW13qbXak7j7rV3/HwLC0fNkDk4R3dEbOwgwCGlM2SJ2vzvKzjuBvk0CUe
nMP7IipXrnchNEppXS09Lf5rWdCuDnLxqvIJrJ/voz5s+pyqlORVyRmaPwKBgGfa
u233DjzpC1fi5Qf1yeKJtVMfZlU6KtXGEUnE9lVU+mtAAINWnXbajMDvCTSHc8xo
6cH2/GzK6WWMXkng1NZ33rKKRi/oCBNYksOBUQ8UBHidjIIA+9fGYqzmBLbcxd8w
sK+cyBfaTyrmMR3VcXajnH7pXyBDOJeWOHV4PX1lAoGAQXihvdKdiav4KnH5BR55
CKXD/eHTyfapO2T1nm4TPmwQRjrPhXn4da1v9HHNtjrDqPPHs20m+IOWgslMth47
xWyJjDxmHrhwuaJI2F/jbTJFGtmoin0EL2F8COkAo77t4tLD66NzIV4vZ/pgO1/H
kmDWkWJDSl+WR47+KoV6BFg=
-----END PRIVATE KEY-----
"""
private_key_pem2 = """
-----BEGIN PUBLIC KEY-----
MIIBCQKCAQBHK5xz3yZYRvsm9aKc4YkmRsbPFwn8gPcn252PjBqDz7cGZaRjA5vS
vQsckif4yzaO3UMZnpZLPg8TXB3c3sFNtmT2/+9Mcm4bp/pAEhOtihlrEECIUtim
vI8uJjdeFKMzF0/8Ap0l2MNJ5R8Vcsw7XkThLiss2g7PRYm32BFuAvLnCGhnXh1Y
kjpts0A+meb0YExsaIokIQ0+pflVs0UV8uVCTboi9SAlF19ycYGvhFIMLm3f8kPr
ZBTT6pHOn9RMpyLjTLetapJ4u+rxrVJzM+Bhinu+gDZnON2eMWZq7lzS6Z861yTk
Z1UAMrJOEU1F/ZWnZ+212j2OK3rZ5B9LAgMBAAE=
-----END PUBLIC KEY-----
"""
n, e, d, p, q = load_private_key_pem(private_key_pem2)
print("n:", n)
print("e:", e)
print("d:", d)
print("p:", p)
print("q:", q)
