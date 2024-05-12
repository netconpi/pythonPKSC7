Запускать из дирректории выше по уровню 

docker build -t pkcs_server <путь к папке>  

docker run -p 8000:8000 -it pkcs_server 


/1 checkCert
'''js
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
'''

/2 validateCRL
'''js
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
'''