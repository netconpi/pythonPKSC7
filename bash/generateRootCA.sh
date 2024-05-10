#!/bin/bash

# Переменные
ROOT_KEY="rootCA.key"
ROOT_CERT="rootCA.crt"
ROOT_CSR="rootCA.csr"
PKCS7_SIGNED="signed.pkcs7"
DETACHED="detached.pkcs7"

# Создание корневого сертификата
generate_root_cert() {
    # Генерация приватного ключа
    openssl genpkey -algorithm RSA -out "$ROOT_KEY" -aes256

    # Создание CSR
    openssl req -new -key "$ROOT_KEY" -out "$ROOT_CSR" -subj "/C=US/ST=California/L=San Francisco/O=My Company/OU=IT Department/CN=example.com"

    # Подписание CSR и создание корневого сертификата
    openssl x509 -req -days 365 -in "$ROOT_CSR" -signkey "$ROOT_KEY" -out "$ROOT_CERT"

    echo "Корневой сертификат и ключ сгенерированы:"
    echo "Приватный ключ: $ROOT_KEY"
    echo "Сертификат: $ROOT_CERT"
}

# Генерация PKCS7 подписи
generate_pkcs7_signature() {
    echo "Введите путь к файлу для подписи:"
    read -r file_path

    if [ ! -f "$file_path" ]; then
        echo "Ошибка: Файл '$file_path' не существует."
        exit 1
    fi

    echo "Хотите открепленную подпись? (y/n):"
    read -r detached

    if [ "$detached" = "y" ]; then
        openssl smime -sign -in "$file_path" -signer "$ROOT_CERT" -inkey "$ROOT_KEY" -outform PEM -out "$DETACHED" -nodetach
        echo "Открепленная подпись сгенерирована: $DETACHED"
    else
        openssl smime -sign -in "$file_path" -signer "$ROOT_CERT" -inkey "$ROOT_KEY" -outform PEM -out "$PKCS7_SIGNED"
        echo "PKCS7 подпись сгенерирована: $PKCS7_SIGNED"
    fi
}

# Основное меню
echo "Выберите действие:"
echo "1. Генерация корневого сертификата"
echo "2. Генерация PKCS7 подписи"
echo "3. Выход"
read -r choice

case $choice in
    1)
        generate_root_cert
        ;;
    2)
        generate_pkcs7_signature
        ;;
    3)
        echo "Выход..."
        exit 0
        ;;
    *)
        echo "Некорректный выбор."
        exit 1
        ;;
esac
