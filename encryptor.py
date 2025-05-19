import base64
import hashlib
from cryptography.fernet import Fernet

def generate_key(password: str) -> bytes:
    return base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())

def encrypt_file(file_path: str, password: str) -> str:
    key = generate_key(password)
    fernet = Fernet(key)

    with open(file_path, 'rb') as file:
        data = file.read()

    encrypted = fernet.encrypt(data)
    encrypted_path = file_path + '.encrypted'

    with open(encrypted_path, 'wb') as enc_file:
        enc_file.write(encrypted)

    return encrypted_path

def decrypt_file(file_path: str, password: str) -> str:
    key = generate_key(password)
    fernet = Fernet(key)

    with open(file_path, 'rb') as file:
        encrypted_data = file.read()

    decrypted_data = fernet.decrypt(encrypted_data)
    decrypted_path = file_path.replace('.encrypted', '.decrypted')

    with open(decrypted_path, 'wb') as dec_file:
        dec_file.write(decrypted_data)

    return decrypted_path
