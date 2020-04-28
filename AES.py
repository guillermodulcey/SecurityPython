from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from cryptography.hazmat.primitives import padding

class AES():
    def __init__(self, key, iv):
        self.cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        self.padder = padding.PKCS7(128).padder()
        self.unpadder = padding.PKCS7(128).unpadder()

    def encrypt(self, message: bytes):
        encryptor = self.cipher.encryptor()
        padded_data = self.padder.update(message)
        padded_data += self.padder.finalize()
        return encryptor.update(padded_data)

    def decrypt(self, cyphertext):
        decryptor = self.cipher.decryptor()
        padded_data = decryptor.update(cyphertext)
        data = self.unpadder.update(padded_data)
        return data + self.unpadder.finalize()