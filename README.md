pip install manifold3d
import time
import os
import requests
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

FPS = 60
frame_time = 60.0 / FPS  # Correção aqui (antes estava 60.0 / FPS)

# -------------------------------
# 🔐 Funções de Criptografia
# -------------------------------

def encrypt(data: bytes, key: bytes):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    encrypted = encryptor.update(padded_data) + encryptor.finalize()
    return iv + encrypted


def decrypt(encrypted_data: bytes, key: bytes):
    iv = encrypted_data[:16]
    data = encrypted_data[16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted = decryptor.update(data) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(decrypted) + unpadder.finalize()


key = os.urandom(32)  # AES-256


# -------------------------------
# 🌎 Verificação de país
# -------------------------------

def verificar_brasil():
    try:
        response = requests.get("https://ipapi.co/json/", timeout=5)
        data = response.json()
        return data.get("country") == "BR"
    except:
        return False


if not verificar_brasil():
    print("Software disponível apenas no Brasil.")
    exit()


# -------------------------------
# 🔁 Loop principal (60 FPS)
# -------------------------------

while True:
    start = time.time()

    print("Rodando frame...")

    elapsed = time.time() - start
    sleep_time = frame_time - elapsed
    if sleep_time > 0:
        time.sleep(sleep_time)
