from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os


class Blowfish:
    def __init__(self):
        self.key = None

    def generate_key(self):
        self.key = os.urandom(32)
        with open('blowfish.key', 'wb') as f:
            f.write(self.key)

    def encrypt_message(self, message):
        iv = os.urandom(8)
        cipher = Cipher(algorithms.Blowfish(self.key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = iv + encryptor.update(message) + encryptor.finalize()
        return ciphertext

    def decrypt_message(self, ciphertext):
        iv = ciphertext[:8]
        ciphertext = ciphertext[8:]
        cipher = Cipher(algorithms.Blowfish(self.key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext
