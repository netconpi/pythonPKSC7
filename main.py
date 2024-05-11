
# PKCS7
from crl import getCRLInfo
from fastapi import FastAPI, File, UploadFile
from typing import List
import os

app = FastAPI()


@app.post("/upload-files/")
async def create_upload_files(files: List[UploadFile] = File(...)):
    for file in files:
        contents = await file.read()
        file_path = f'uploaded_files/{file.filename}'
        with open(file_path, 'wb') as f:
            f.write(contents)
        getCRLInfo(file_path)
    return {"message": f"Successfully saved {len(files)} files."}

def main(): 
    os.makedirs('uploaded_files', exist_ok=True)
    # getCRLInfo('/Users/ntcad/gitPrjs/pythonPKSC7/additionalFiles/russiantrustedca.pem')

if __name__ == '__main__':
    import uvicorn
    main()
    uvicorn.run(app, host="0.0.0.0", port=8000)
