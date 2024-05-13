# PKCS7
from crl import getCRLInfo
from bash import verify_signature
from fastapi import FastAPI, File, UploadFile
from typing import List
import os
import shutil

app = FastAPI()


@app.post("/validateCRL/")
async def create_upload_files(files: List[UploadFile] = File(...)):
    for file in files:
        contents = await file.read()
        file_path = f'uploaded_files/{file.filename}'
        with open(file_path, 'wb') as f:
            f.write(contents)

        if getCRLInfo(file_path):
            return {"message": f"Not revoked"}
        else:
            return {"message": f"revoked"}


@app.post("/checkCert/")
async def upload_files(signed_file: UploadFile = File(...),
                       root_certificate: UploadFile = File(...),
                       content_file: UploadFile = File(...)):
    """
    Uploads three files and returns a dictionary of their paths.
    """
    save_dir = 'uploaded_files'

    # Saving the files
    paths = {
        "signed_file": save_upload_file(signed_file, save_dir),
        "root_certificate": save_upload_file(root_certificate, save_dir),
        "content_file": save_upload_file(content_file, save_dir)
    }

    return verify_signature(paths['signed_file'], paths['root_certificate'], paths['content_file'])


def save_upload_file(upload_file, directory):
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
