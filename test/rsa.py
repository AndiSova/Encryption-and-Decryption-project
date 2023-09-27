import rsa


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
