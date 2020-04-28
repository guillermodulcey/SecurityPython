import time

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

from cryptography.hazmat.primitives.asymmetric import rsa

class RSA():
    def __init__(self):
        self.private_key = None
        self.public_key = None
        self.entity_key = None

    def generateKeys(self, size):
        # self.size = size
        # f = open(f'time_key_{self.size}.txt','w')
        # inicio = time.time()
        self.private_key = rsa.generate_private_key(public_exponent=65537,key_size=size,backend=default_backend())
        # fin = time.time()
        self.public_key = self.private_key.public_key()
        # fin2 = time.time()
        # f.write(f'Time private key: {fin-inicio}\n')
        # f.write(f'Time public key: {fin2-fin}')
        # f.close()

    def sign(self, message):
        return self.private_key.sign(message,padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())

    def verify(self, signature, message):
        try:
            if self.entity_key is None:
                self.public_key.verify(signature,message,padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
            else:
                self.entity_key.verify(signature,message,padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
        except:
            return False
        else:
            return True
    
    def encrypt(self, message):
        if self.entity_key is None:
            return self.public_key.encrypt(message,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
        else:
            return self.entity_key.encrypt(message,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))

    def decrypt(self, cyphertext):
        return self.private_key.decrypt(cyphertext,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))

    # def saveKeys(self):
    #     f = open(f'private_{self.size}.pem','wb')
    #     pem = self.private_key.private_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.PKCS8,encryption_algorithm=serialization.NoEncryption())
    #     f.write(pem)
    #     f.close()
    #     f = open(f'public_{self.size}.pem','wb')
    #     pem = self.public_key.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)
    #     f.write(pem)
    #     f.close()

    # Setters y Getters:

    def getPrivateKey(self):
        return self.private_key

    def getPublicKey(self):
        return self.public_key

    def getEntityKey(self):
        return self.entity_key

    def setPrivateKey(self, private_key):
        self.private_key = private_key

    def setPublicKey(self, public_key):
        self.public_key = public_key

    def setEntityKey(self, entity_key):
        self.entity_key = entity_key

    def getKeys(self,path,size):
        f = open(f'{path}/private_{size}.pem','rb')
        self.private_key = serialization.load_pem_private_key(f.read(),password=None,backend=default_backend())
        f.close()
        f = open(f'{path}/public_{size}.pem','rb')
        self.public_key = serialization.load_pem_public_key(f.read(),backend=default_backend())
        f.close()