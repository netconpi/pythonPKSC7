# PKCS7
from crl import getCRLInfo
from bash import verify_signature, verify_pkcs
from fastapi import FastAPI, File, UploadFile
from typing import List, Optional
import os
import shutil

app = FastAPI()


@app.post("/validateCRL/")
async def validate_crl(files: List[UploadFile] = File(...)):
    for file in files:
        contents = await file.read()
        file_path = f'uploaded_files/{file.filename}'
        with open(file_path, 'wb') as f:
            f.write(contents)

        match (getCRLInfo(file_path)):
            case '001':
                return {"message": f"Revoked"}
            case '002':
                return {"message": f"Ok"}
            case '003':
                return {"message": f"CRL Extension Not Found"}
            case _:
                return {"message": f"Error. Check the data"}


@app.post("/checkCert/")
async def check_cert(signed_file: UploadFile = File(...),
                     root_certificate: UploadFile = File(...),
                     content_file: UploadFile = File(...)):
    """
    Uploads three files and returns a dictionary of their paths.
    """

    # Saving the files
    paths = {
        "signed_file": save_upload_file(signed_file),
        "root_certificate": save_upload_file(root_certificate),
        "content_file": save_upload_file(content_file)
    }

    return verify_signature(paths['signed_file'], paths['root_certificate'], paths['content_file'])


@app.post("/verifyPKCS/")
async def verify_pkcs7_signature(signed_file: UploadFile = File(...),
                                 root_certificate: UploadFile = File(...),
                                 content_file: Optional[UploadFile] = File(None)):
    """
    Endpoint to upload a signed file, CA certificate, and optionally a content file,
    then verify the PKCS#7 signature.
    """
    paths = {
        "signed_file": save_upload_file(signed_file),
        "root_certificate": save_upload_file(root_certificate)
    }

    # For detached signatures, ensure content file is provided
    if content_file:
        paths["content_file"] = save_upload_file(content_file)
        return verify_pkcs(paths['signed_file'], paths['root_certificate'], paths['content_file'])
    else:
        return verify_pkcs(paths['signed_file'], paths['root_certificate'])


def save_upload_file(upload_file, directory='uploaded_files'):
    try:
        directory += '/'
        file_location = directory + upload_file.filename
        with open(file_location, "wb") as buffer:
            shutil.copyfileobj(upload_file.file, buffer)
        return str(file_location)
    finally:
        upload_file.file.close()


def main():
    os.makedirs('uploaded_files', exist_ok=True)


if __name__ == '__main__':
    import uvicorn

    main()
    uvicorn.run(app, host="0.0.0.0", port=8000)
