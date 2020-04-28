import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

class KDF():
    def __init__(self):
        pass

    def getAKey(self,size):
        return HKDF(algorithm=hashes.SHA256(),length=size,salt=os.urandom(16),info=b'123456',backend=default_backend()).derive(b'random')