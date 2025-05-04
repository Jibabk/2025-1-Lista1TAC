import secrets
import time
import base64
from Crypto.Cipher import AES

# Lê a mensagem do arquivo
with open("mensagem.txt", "rb") as file:
    message = file.read()
    if len(message) % 16 != 0:
        message += b'\x00' * (16 - len(message) % 16)
    data = message.decode('utf-8').encode('utf-8')

# Gera chave e IV
key = secrets.token_bytes(16)
iv = secrets.token_bytes(16)
print(f"Chave: {key.hex()}")
print(f"IV: {iv.hex()}")

# Cria pasta de saída se necessário
import os
os.makedirs("cifras", exist_ok=True)

import math

# Função para calcular a entropia de Shannon
# A entropia de Shannon é uma medida da incerteza ou aleatoriedade de um conjunto de dados.
def shannon_entropy(data: bytes):
    freq = {b: data.count(b) / len(data) for b in set(data)}
    entropy = -sum(p * math.log2(p) for p in freq.values())
    return entropy

# Função para cifrar, medir tempo, entropia e salvar em base64
def encrypt_and_save(mode_name, cipher):
    start_time = time.perf_counter()
    ciphertext = cipher.encrypt(data)
    end_time = time.perf_counter()
    entropy = shannon_entropy(ciphertext)

    base64_cipher = base64.b64encode(ciphertext)

    with open(f"cifras/{mode_name}_cipher.txt", "wb") as file:
        file.write(base64_cipher)

    print(f"{mode_name:<6} | {end_time - start_time:.6f} s | Shannon Entropy (bits por byte): {entropy:.4f} | {base64_cipher[:60].decode()}...")

# ECB
ECBcipher = AES.new(key, AES.MODE_ECB)
encrypt_and_save("ECB", ECBcipher)

# CBC
CBCcipher = AES.new(key, AES.MODE_CBC, iv=iv)
encrypt_and_save("CBC", CBCcipher)

# CFB
CFBcipher = AES.new(key, AES.MODE_CFB, iv=iv)
encrypt_and_save("CFB", CFBcipher)

# OFB
OFBcipher = AES.new(key, AES.MODE_OFB, iv=iv)
encrypt_and_save("OFB", OFBcipher)

# CTR (usa nonce no lugar de IV)
CTRcipher = AES.new(key, AES.MODE_CTR)
encrypt_and_save("CTR", CTRcipher)
