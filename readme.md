Запускать из дирректории выше по уровню 

```commandline
docker build -t pkcs_server <путь к папке>  
```

```commandline
docker run -p 8000:8000 -it pkcs_server 
```


/1 checkCert
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

/2 validateCRL
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
