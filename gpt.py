from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
import os
import datetime
import asn1crypto.cms
import asn1crypto.core
import asn1crypto.pem


class CryptedDataGenerator:
    def __init__(self, output_directory):
        self.output_directory = output_directory
        os.makedirs(self.output_directory, exist_ok=True)

    def generate_root_certificate(self, common_name):
        # Создаем ключи корневого сертификата
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        # Пишем закрытый ключ в файл
        private_key_path = os.path.join(self.output_directory, 'root_private_key.pem')
        with open(private_key_path, 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.PKCS8,
                encryption_algorithm=NoEncryption()
            ))

        # Создаем сертификат
        name = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, common_name)])
        subject = issuer = name
        certificate = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=3650)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True
        ).sign(private_key, hashes.SHA256(), default_backend())

        # Пишем сертификат в файл
        root_cert_path = os.path.join(self.output_directory, 'root_certificate.pem')
        with open(root_cert_path, 'wb') as f:
            f.write(certificate.public_bytes(Encoding.PEM))

        return private_key, certificate

    def sign_data_pkcs7(self, data, signer_private_key, signer_certificate, detached=False):
        # Создаем подписанную CMS структуру PKCS#7
        signed_data = asn1crypto.cms.SignedData({
            'version': 'v1',
            'digest_algorithms': [{'algorithm': 'sha256'}],
            'encap_content_info': {
                'content_type': 'data',
                'content': data if not detached else None
            },
            'certificates': [asn1crypto.x509.Certificate.load(signer_certificate.public_bytes(Encoding.DER))],
            'signer_infos': [{
                'version': 'v1',
                'sid': asn1crypto.cms.SignerIdentifier({
                    'issuer_and_serial_number': {
                        'issuer': asn1crypto.x509.Name.build(signer_certificate.subject),
                        'serial_number': signer_certificate.serial_number
                    }
                }),
                'digest_algorithm': {'algorithm': 'sha256'},
                'signature_algorithm': {'algorithm': 'rsassa_pkcs1v15'},
                'signature': signer_private_key.sign(
                    data,
                    padding.PKCS1v15(),
                    hashes.SHA256()
                )
            }]
        })

        content_info = asn1crypto.cms.ContentInfo({
            'content_type': 'signed_data',
            'content': signed_data
        })

        return content_info.dump()

    def generate_pkcs7_signature(self, data, common_name, detached=False):
        private_key, certificate = self.generate_root_certificate(common_name)
        pkcs7_signature = self.sign_data_pkcs7(data, private_key, certificate, detached)

        filename = 'pkcs7_signature_detached' if detached else 'pkcs7_signature_attached'
        signature_path = os.path.join(self.output_directory, f'{filename}.p7b')
        with open(signature_path, 'wb') as f:
            f.write(pkcs7_signature)

        return signature_path


# Пример использования
if __name__ == "__main__":
    generator = CryptedDataGenerator("output")
    data = b"Sample data to be signed"
    generator.generate_pkcs7_signature(data, "Root CA", detached=False)
    generator.generate_pkcs7_signature(data, "Root CA", detached=True)
