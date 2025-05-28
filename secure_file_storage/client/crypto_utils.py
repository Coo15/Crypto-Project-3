import secrets
import hashlib
import hmac
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.exceptions import InvalidTag
import os

def generate_storage_id():
    master_key = secrets.token_bytes(32)
    storage_id = hmac.new(
        master_key, b"my-app-storage", hashlib.sha256
    ).hexdigest()
    return base64.b64encode(master_key).decode("utf-8"), storage_id

def generate_fek():
    return secrets.token_bytes(32)

def encrypt_file(file_path, master_key_b64):
    master_key = base64.b64decode(master_key_b64)
    fek = generate_fek()

    # Read file contents
    with open(file_path, "rb") as f:
        file_contents = f.read()

    # Encrypt file contents using FEK
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(fek), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(file_contents) + encryptor.finalize()
    file_nonce = iv
    file_tag = encryptor.tag

    # Encrypt FEK using master key
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(master_key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_fek = encryptor.update(fek) + encryptor.finalize()
    fek_nonce = iv
    fek_tag = encryptor.tag

    return (
        ciphertext,
        file_nonce,
        file_tag,
        encrypted_fek,
        fek_nonce,
        fek_tag,
    )


def decrypt_file(
    ciphertext,
    file_nonce,
    file_tag,
    encrypted_fek,
    fek_nonce,
    fek_tag,
    master_key_b64,
):
    master_key = base64.b64decode(master_key_b64)

    # Decrypt FEK
    cipher = Cipher(algorithms.AES(master_key), modes.GCM(fek_nonce, fek_tag), backend=default_backend())
    decryptor = cipher.decryptor()
    # decryptor.authenticate_additional_data(file_nonce) # This is incorrect
    try:
        fek = decryptor.update(encrypted_fek) + decryptor.finalize()
    except InvalidTag:
        raise Exception("Invalid tag - FEK decryption failed")

    # Decrypt file contents
    cipher = Cipher(algorithms.AES(fek), modes.GCM(file_nonce, file_tag), backend=default_backend())
    decryptor = cipher.decryptor()
    # decryptor.authenticate_additional_data(encrypted_fek) # This is incorrect
    try:
        file_contents = decryptor.update(ciphertext) + decryptor.finalize()
    except InvalidTag:
        raise Exception("Invalid tag - File decryption failed")

    return file_contents

# handles encryption (FEK generation, file encryption/decryption)
