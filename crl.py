import OpenSSL.crypto
import requests
import os
import OpenSSL.crypto
from cryptography.x509.oid import ExtensionOID
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

def load_certificate(cert_path):
    with open(cert_path, 'rb') as file:
        cert_content = file.read()
    
    # Определяем тип файла по содержимому
    try:
        return OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_content)
    except OpenSSL.crypto.Error:
        # Если не удалось загрузить как PEM, пробуем как DER
        return OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert_content)

def get_crl_distribution_urls(certificate_path):

    # Загрузите сертификат (предполагается, что у вас есть файл сертификата в формате PEM)
    with open(certificate_path, "rb") as cert_file:
        cert_data = cert_file.read()
        certificate = x509.load_pem_x509_certificate(cert_data, default_backend())

    # Словарь для хранения данных CRL Distribution Points
    crl_distribution_data = []

    # Попытка извлечь расширение CRL Distribution Points
    try:
        crl_distribution_points = certificate.extensions.get_extension_for_oid(
            ExtensionOID.CRL_DISTRIBUTION_POINTS
        )
        distribution_points = crl_distribution_points.value

        # Извлечение информации о каждой точке распространения CRL
        for dp in distribution_points:
            dp_info = {}
            if dp.full_name:
                dp_info['URLs'] = [name.value for name in dp.full_name]
            if dp.relative_name:
                dp_info['Relative Name'] = dp.relative_name.rfc4514_string()
            if dp.reasons:
                dp_info['Reasons'] = dp.reasons
            if dp.crl_issuer:
                dp_info['CRL Issuer'] = [issuer.rfc4514_string() for issuer in dp.crl_issuer]
            crl_distribution_data.append(dp_info)

    except x509.ExtensionNotFound:
        print("CRL Distribution Points extension not found in this certificate.")

    # Вывод словаря с данными CRL Distribution Points
    return crl_distribution_data


def download_crl(crl_url):
    response = requests.get(crl_url)
    if response.status_code == 200:
        return OpenSSL.crypto.load_crl(OpenSSL.crypto.FILETYPE_ASN1, response.content)
    else:
        print(f"Failed to download CRL from {crl_url}")
        return None

def is_certificate_revoked(certificate, crl):
    # Проверяем, есть ли сертификат в списке отозванных
    revoked = crl.get_revoked()
    if revoked:
        cert_serial = certificate.get_serial_number()
        for r in revoked:
            if int(r.get_serial(), 16) == cert_serial:
                return True
    return False

def der_to_pem(der_path, pem_path):
    # Чтение сертификата в формате DER из файла
    with open(der_path, "rb") as file:
        der_data = file.read()
        certificate = x509.load_der_x509_certificate(der_data, default_backend())

    # Конвертация сертификата в формат PEM
    pem_data = certificate.public_bytes(encoding=serialization.Encoding.PEM)

    # Запись сертификата в формате PEM в файл
    with open(pem_path, "wb") as file:
        file.write(pem_data)
    print(f"Certificate has been converted to PEM format and saved to {pem_path}")


def runParsing(cert_path):
    certificate = load_certificate(cert_path)
    crl_url = get_crl_distribution_urls(cert_path)
    if crl_url:
        # Загрузка CRL
        for crl in crl_url:
            crl = download_crl(crl['URLs'][0])
            if crl:
                # Проверка, отозван ли сертификат
                if is_certificate_revoked(certificate, crl):
                    return False
                else:
                    return True
    else:
        return False


def getCRLInfo(cert_path):
    if cert_path.lower().endswith('.pem'):
        return runParsing(cert_path)
    else: 
        der_to_pem(cert_path, '/Users/ntcad/gitPrjs/pythonPKSC7/converted.pem')
        return runParsing('/Users/ntcad/gitPrjs/pythonPKSC7/converted.pem')

