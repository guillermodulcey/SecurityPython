import datetime

from cryptography import x509
from cryptography.x509.oid import NameOID

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import padding

from RSA import RSA

class Certificate():
    def __init__(self,private_key,public_key):
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, u"CO"),
                              x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Cauca"),
                              x509.NameAttribute(NameOID.LOCALITY_NAME, u"Popayan"),
                              x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Cinvestav"),
                              x509.NameAttribute(NameOID.COMMON_NAME, u"hdulcey")])

        self.cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer
                                       ).public_key(public_key
                                       ).serial_number(x509.random_serial_number()
                                       ).not_valid_before(datetime.datetime.utcnow()
                                       ).not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=100)
                                       ).add_extension(x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),critical=False
                                       ).sign(private_key, hashes.SHA256(), default_backend())

    def getCertificate(self):
        return self.cert

    def validateCertificate(self, cert, public_key):
        try:
            public_key.verify(cert.signature,cert.tbs_certificate_bytes,padding.PKCS1v15(),cert.signature_hash_algorithm)
        except:
            return False
        else:
            return True