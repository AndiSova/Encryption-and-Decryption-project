from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os
import rsa
import warnings
from cryptography.utils import CryptographyDeprecationWarning
warnings.simplefilter("ignore", CryptographyDeprecationWarning)


def pad(data, block_size):
    padder = padding.PKCS7(block_size).padder()
    padded_data = padder.update(data)
    padded_data += padder.finalize()
    return padded_data


def unpad(padded_data, block_size):
    unpadder = padding.PKCS7(block_size).unpadder()
    data = unpadder.update(padded_data)
    data += unpadder.finalize()
    return data


class AES:
    def __init__(self):
        self.key = None

    def generate_key(self):
        self.key = os.urandom(32)
        with open('aes.key', 'wb') as f:
            f.write(self.key)

    def encrypt_message(self, message):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padded_message = pad(message, 128)
        ciphertext = iv + encryptor.update(padded_message) + encryptor.finalize()
        return ciphertext

    def decrypt_message(self, ciphertext):
        iv = ciphertext[:16]
        ciphertext = ciphertext[16:]
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        plaintext = unpad(padded_plaintext, 128)
        return plaintext


class RSA:
    def __init__(self):
        self.public_key = None
        self.private_key = None

    def generate_keys(self):
        (self.public_key, self.private_key) = rsa.newkeys(2048)

        with open('private.pem', 'wb') as f:
            f.write(self.private_key.save_pkcs1())

        with open('public.pem', 'wb') as f:
            f.write(self.public_key.save_pkcs1())

    def encrypt_message(self, message):
        ciphertext = rsa.encrypt(message, self.public_key)
        return ciphertext

    def decrypt_message(self, ciphertext):
        plaintext = rsa.decrypt(ciphertext, self.private_key)
        return plaintext


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
        padded_message = pad(message, 64)
        ciphertext = iv + encryptor.update(padded_message) + encryptor.finalize()
        return ciphertext

    def decrypt_message(self, ciphertext):
        iv = ciphertext[:8]
        ciphertext = ciphertext[8:]
        cipher = Cipher(algorithms.Blowfish(self.key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        plaintext = unpad(padded_plaintext, 64)
        return plaintext


class EncryptionApp:
    def __init__(self):
        self.rsa = RSA()
        self.aes = AES()
        self.blowfish = Blowfish()

    def generate_keys(self):
        self.rsa.generate_keys()
        self.aes.generate_key()
        self.blowfish.generate_key()

    def encrypt_message(self, message, algorithm):
        if algorithm == 'RSA':
            return self.rsa.encrypt_message(message)
        elif algorithm == 'AES':
            return self.aes.encrypt_message(message)
        elif algorithm == 'Blowfish':
            return self.blowfish.encrypt_message(message)
        else:
            raise ValueError(f'Unknown algorithm: {algorithm}')

    def decrypt_message(self, ciphertext, algorithm):
        if algorithm == 'RSA':
            return self.rsa.decrypt_message(ciphertext)
        elif algorithm == 'AES':
            return self.aes.decrypt_message(ciphertext)
        elif algorithm == 'Blowfish':
            return self.blowfish.decrypt_message(ciphertext)
        else:
            raise ValueError(f'Unknown algorithm: {algorithm}')

    def encrypt_message_all(self, message):
        print(f'Original message: {message}')
        aes_ciphertext = self.aes.encrypt_message(message)
        print(f'AES ciphertext: {aes_ciphertext.hex()}')
        blowfish_ciphertext = self.blowfish.encrypt_message(aes_ciphertext)
        print(f'Blowfish ciphertext: {blowfish_ciphertext.hex()}')
        rsa_ciphertext = self.rsa.encrypt_message(blowfish_ciphertext)
        print(f'RSA ciphertext: {rsa_ciphertext.hex()}')
        return rsa_ciphertext

    def decrypt_message_all(self, ciphertext):
        print(f'Original ciphertext: {ciphertext.hex()}')
        blowfish_plaintext = self.rsa.decrypt_message(ciphertext)
        print(f'RSA plaintext: {blowfish_plaintext.hex()}')
        aes_plaintext = self.blowfish.decrypt_message(blowfish_plaintext)
        print(f'Blowfish plaintext: {aes_plaintext.hex()}')
        plaintext = self.aes.decrypt_message(aes_plaintext)
        print(f'AES plaintext: {plaintext.decode("utf-8")}')
        return plaintext

    def run(self):
        keys_generated = False
        while True:
            print('Select an option:')
            print('1. Generate keys')
            print('2. Encrypt message')
            print('3. Decrypt message')
            print('4. Encrypt message using all algorithms')
            print('5. Decrypt message using all algorithms')
            print('6. Quit')
            option = input('> ')

            if option == '1':
                self.generate_keys()
                keys_generated = True
                print('Keys generated and stored on disk.')
            elif option == '2':
                if not keys_generated:
                    print('Please generate keys first.')
                    continue
                message = input('Enter a message to encrypt: ').encode('utf-8')
                print('Select an algorithm:')
                print('1. RSA')
                print('2. AES')
                print('3. Blowfish')
                algorithm = input('> ')
                if algorithm == '1':
                    algorithm = 'RSA'
                elif algorithm == '2':
                    algorithm = 'AES'
                elif algorithm == '3':
                    algorithm = 'Blowfish'
                else:
                    print('Unknown algorithm.')
                    continue
                ciphertext = self.encrypt_message(message, algorithm)
                print(f'Ciphertext: {ciphertext.hex()}')
            elif option == '3':
                if not keys_generated:
                    print('Please generate keys first.')
                    continue
                try:
                    ciphertext = bytes.fromhex(input('Enter a ciphertext to decrypt: '))
                except ValueError:
                    print('Invalid ciphertext. Please enter a valid hexadecimal string.')
                    continue
                print('Select an algorithm:')
                print('1. RSA')
                print('2. AES')
                print('3. Blowfish')
                algorithm = input('> ')
                if algorithm == '1':
                    algorithm = 'RSA'
                elif algorithm == '2':
                    algorithm = 'AES'
                elif algorithm == '3':
                    algorithm = 'Blowfish'
                else:
                    print('Unknown algorithm.')
                    continue
                try:
                    plaintext = self.decrypt_message(ciphertext, algorithm)
                    print(f'Plaintext: {plaintext.decode("utf-8")}')
                except Exception as e:
                    print(f'An error occurred during decryption: {e}')
                    continue
            elif option == '4':
                if not keys_generated:
                    print('Please generate keys first.')
                    continue
                message = input('Enter a message to encrypt: ').encode('utf-8')
                ciphertext = self.encrypt_message_all(message)
            elif option == '5':
                if not keys_generated:
                    print('Please generate keys first.')
                    continue
                try:
                    ciphertext = bytes.fromhex(input('Enter a ciphertext to decrypt: '))
                except ValueError:
                    print('Invalid ciphertext. Please enter a valid hexadecimal string.')
                    continue
                try:
                    plaintext = self.decrypt_message_all(ciphertext)
                except Exception as e:
                    print(f'An error occurred during decryption: {e}')
                    continue
            elif option == '6':
                break
            else:
                print('Unknown option.')


if __name__ == '__main__':
    app = EncryptionApp()
    app.run()
