# PKCS7: basic validation

## build project:

```commandline
docker build -t pkcs_server <путь к папке>  
```

```commandline
docker run -p 8000:8000 -it pkcs_server 
```

## API:

### 1. /checkCert/
```js
const formdata = new FormData();
formdata.append("signed_file", fileInput.files[0], "converted.pem");
formdata.append("root_certificate", fileInput.files[0], "russiantrustedca.pem");
formdata.append("content_file", fileInput.files[0], "test.txt");

const requestOptions = {
    method: "POST",
    body: formdata,
    redirect: "follow"
};

fetch("http://0.0.0.0:8000/checkCert/", requestOptions)
    .then((response) => response.text())
    .then((result) => console.log(result))
    .catch((error) => console.error(error));
```

Examples of output:

```json
{
    "message": "Failed",
    "executed": "openssl cms -verify -in uploaded_files/signedfile.p7m -CAfile uploaded_files/ca-chain.cert.pem -inform DER -content uploaded_files/testfile.txt -out verified.txt",
    "path": "/Users/ntcad/gitPrjs/pythonPKSC7"
}
```

```json
{
    "message": "Verified",
    "std": "CMS Verification successful\n",
    "executed": "openssl cms -verify -in uploaded_files/signedfile.p7m -CAfile uploaded_files/RootCA.pem -inform DER -content uploaded_files/testfile.txt -out verified.txt",
    "path": "/Users/ntcad/gitPrjs/pythonPKSC7"
}
```

### 2. /validateCRL/
```js
const formdata = new FormData();
formdata.append("files", fileInput.files[0], "converted.pem");

const requestOptions = {
    method: "POST",
    body: formdata,
    redirect: "follow"
};

fetch("http://0.0.0.0:8000/validateCRL/", requestOptions)
    .then((response) => response.text())
    .then((result) => console.log(result))
    .catch((error) => console.error(error));
```

Ответы (строки):

1. Revoked -> отозван
2. Ok -> все хорошо
3. CRL Extension Not Found -> нет CRL
4. Error. Check the data -> ошибка в переданных данных 

### 3. /verifyPKCS/

#### Attached

```js
const formdata = new FormData();
formdata.append("signed_file", fileInput.files[0], "UserAttached.p7m");
formdata.append("root_certificate", fileInput.files[0], "CAchain.pem");
formdata.append("content_file", fileInput.files[0], "User.txt");

const requestOptions = {
  method: "POST",
  body: formdata,
  redirect: "follow"
};

fetch("http://0.0.0.0:8000/verifyPKCS/", requestOptions)
  .then((response) => response.text())
  .then((result) => console.log(result))
  .catch((error) => console.error(error));
```

```json
{
    "message": "Failed",
    "error_details": "Command '['openssl', 'smime', '-verify', '-in', 'uploaded_files/UserAttached.p7m', '-CAfile', 'uploaded_files/CAchain.pem', '-inform', 'PEM', '-content', 'uploaded_files/User.txt', '-out', 'verified_message.txt']' returned non-zero exit status 4.",
    "command_executed": "openssl smime -verify -in uploaded_files/UserAttached.p7m -CAfile uploaded_files/CAchain.pem -inform PEM -content uploaded_files/User.txt -out verified_message.txt"
}
```

#### Detached

```js
const formdata = new FormData();
formdata.append("signed_file", fileInput.files[0], "UserAttached.p7m");
formdata.append("root_certificate", fileInput.files[0], "CAchain.pem");

const requestOptions = {
  method: "POST",
  body: formdata,
  redirect: "follow"
};

fetch("http://0.0.0.0:8000/verifyPKCS/", requestOptions)
  .then((response) => response.text())
  .then((result) => console.log(result))
  .catch((error) => console.error(error));
```

```json
{
    "message": "Failed",
    "error_details": "Command '['openssl', 'smime', '-verify', '-in', 'uploaded_files/UserAttached.p7m', '-CAfile', 'uploaded_files/CAchain.pem', '-inform', 'PEM', '-out', 'verified_message.txt']' returned non-zero exit status 4.",
    "command_executed": "openssl smime -verify -in uploaded_files/UserAttached.p7m -CAfile uploaded_files/CAchain.pem -inform PEM -out verified_message.txt"
}
```

В контексте PKCS#7, который широко используется для подписи и шифрования сообщений в формате S/MIME, существует два варианта файла: **присоединённый (attached)** и **отсоединённый (detached)**. Понимание разницы между этими двумя формами поможет в правильной реализации и использовании этих файлов.

##### Присоединённый PKCS#7 (Attached PKCS#7)

В присоединённом формате PKCS#7 содержимое сообщения включено внутрь самого файла PKCS#7. Это означает, что подписанные данные содержатся вместе с цифровой подписью и сертификатами в одном файле. Это удобно для пересылки, так как получателю нужен только один файл, чтобы проверить подпись и прочитать содержимое.

Пример создания присоединённого PKCS#7 файла в OpenSSL:

```bash
openssl smime -sign -in message.txt -text -signer userCert.pem -inkey userKey.pem -out mail.p7m -outform PEM
```
##### Отсоединённый PKCS#7 (Detached PKCS#7)

В отсоединённом формате PKCS#7, само содержимое сообщения не включено в файл PKCS#7. Вместо этого, файл PKCS#7 содержит только цифровую подпись и используемые сертификаты. Само содержимое отправляется отдельно, что уменьшает размер файла подписи и позволяет получателям проверять подпись, не изменяя исходное сообщение.

Пример создания отсоединённого PKCS#7 файла в OpenSSL:

```bash
openssl smime -sign -in message.txt -signer userCert.pem -inkey userKey.pem -out mail.p7s -outform PEM -nodetach
```
##### Проверка подписи

Независимо от того, используется присоединённый или отсоединённый формат, процесс проверки подписи остаётся похожим. **Для отсоединённой подписи вам нужно будет указать файл с содержимым при верификации**:

```bash
openssl smime -verify -in mail.p7s -content message.txt -CAfile caCert.pem -out verified_content.txt
```
Для присоединённой подписи файл с содержимым указывать не нужно:

```bash
openssl smime -verify -in mail.p7m -CAfile caCert.pem -out verified_content.txt
```
В каждом из этих случаев, openssl smime -verify проверит подпись, используя указанный корневой сертификат (или цепочку сертификатов, если нужно). Это помогает гарантировать, что сообщение не было изменено после подписания, и что подпись действительно принадлежит отправителю.

