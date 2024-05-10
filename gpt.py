from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from PyPDF2 import PdfReader
import datetime
import asn1crypto.cms
import asn1crypto.x509

# Генерация сертификата
def generate_certificate(common_name, country, state, locality, organization, email):
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
        x509.NameAttribute(NameOID.LOCALITY_NAME, locality),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, email),
    ])
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        # Сертификат действителен 1 год
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(common_name)]),
        critical=False
    ).sign(key, hashes.SHA256(), default_backend())
    
    return cert, key

# Чтение данных PDF файла
def read_pdf_data(pdf_path):
    with open(pdf_path, 'rb') as f:
        reader = PdfReader(f)
        pdf_data = ''.join(page.extract_text() for page in reader.pages)
    return pdf_data.encode('utf-8')

# Подписывание данных с использованием RSA
def sign_data(data, private_key):
    signature = private_key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return signature

# Создание PKCS #7 контейнера
def create_pkcs7(cert, key, data):
    # Создаем подпись с использованием приватного ключа
    signed_data = sign_data(data, key)
    
    # Преобразуем сертификат в ASN.1 формат
    cert_asn1 = asn1crypto.x509.Certificate.load(cert.public_bytes(serialization.Encoding.DER))
    
    # Рассчитываем хэш данных
    hash_obj = hashes.Hash(hashes.SHA256(), default_backend())
    hash_obj.update(data)
    digest = hash_obj.finalize()
    
    # Создаем информацию о подписчике
    signer_info = asn1crypto.cms.SignerInfo({
        'version': 'v1',
        'sid': asn1crypto.cms.SignerIdentifier({
            'issuer_and_serial_number': asn1crypto.cms.IssuerAndSerialNumber({
                'issuer': cert_asn1.issuer,
                'serial_number': cert_asn1.serial_number
            })
        }),
        'digest_algorithm': {'algorithm': 'sha256'},
        'signed_attrs': asn1crypto.cms.CMSAttributes([
            {'type': 'content_type', 'values': ['data']},
            {'type': 'message_digest', 'values': [digest]},
        ]),
        'signature_algorithm': {'algorithm': 'rsassa_pkcs1v15'},
        'signature': signed_data
    })
    
    # Создаем SignedData структуру
    signed_data = asn1crypto.cms.SignedData({
        'version': 'v1',
        'digest_algorithms': [{'algorithm': 'sha256'}],
        'encap_content_info': {'content_type': 'data', 'content': data},
        'certificates': [cert_asn1],
        'signer_infos': [signer_info]
    })
    
    # Создаем ContentInfo структуру
    content_info = asn1crypto.cms.ContentInfo({
        'content_type': 'signed_data',
        'content': signed_data
    })
    
    return content_info.dump()

# Сохранение PKCS #7 файла
def save_pkcs7_file(output_path, pkcs7_data):
    with open(output_path, 'wb') as f:
        f.write(pkcs7_data)

# Экспорт сертификата и ключа в файлы PEM
def export_certificate_and_key(cert, key, cert_path, key_path, key_password=None):
    with open(cert_path, 'wb') as cert_file:
        cert_file.write(cert.public_bytes(serialization.Encoding.PEM))
    
    encryption_algorithm = serialization.BestAvailableEncryption(key_password) if key_password else serialization.NoEncryption()
    
    with open(key_path, 'wb') as key_file:
        key_file.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=encryption_algorithm
        ))

# Основная функция
def main(pdf_path, output_path, cert_info, cert_export_path, key_export_path, key_password=None):
    cert, key = generate_certificate(
        common_name=cert_info['common_name'],
        country=cert_info['country'],
        state=cert_info['state'],
        locality=cert_info['locality'],
        organization=cert_info['organization'],
        email=cert_info['email']
    )
    pdf_data = read_pdf_data(pdf_path)
    pkcs7_data = create_pkcs7(cert, key, pdf_data)
    save_pkcs7_file(output_path, pkcs7_data)
    export_certificate_and_key(cert, key, cert_export_path, key_export_path, key_password)

# Пример вызова функции
if __name__ == '__main__':
    pdf_path = 'template.pdf'
    output_path = 'signed_certificate.p7b'
    cert_export_path = 'certificate.pem'
    key_export_path = 'private_key.pem'
    cert_info = {
        'common_name': 'example.com',
        'country': 'US',
        'state': 'California',
        'locality': 'San Francisco',
        'organization': 'Example Inc.',
        'email': 'info@example.com'
    }
    key_password = 'your_password'.encode('utf-8')  # Установите пароль для приватного ключа или оставьте как `None`
    
    main(pdf_path, output_path, cert_info, cert_export_path, key_export_path, key_password)
