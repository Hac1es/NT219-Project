from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.responses import FileResponse
import subprocess
import tempfile
import shutil
import os

app = FastAPI()

@app.post("/submit-csr")
async def handle_csr(csr: UploadFile = File(...)):
    try:
        # Lưu file tạm
        with tempfile.NamedTemporaryFile(suffix=".csr", delete=False) as csr_file:
            csr_path = csr_file.name
            shutil.copyfileobj(csr.file, csr_file)

        # Chuẩn bị nơi xuất chứng chỉ
        with tempfile.NamedTemporaryFile(suffix=".crt", delete=False) as cert_file:
            cert_path = cert_file.name

        # Ký CSR bằng openssl (phải có sẵn ca.crt và ca.key trong thư mục chạy)
        subprocess.run([
            "openssl", "x509", "-req",
            "-in", csr_path,
            "-CA", "sbvCert.crt",
            "-CAkey", "rootCA.key",
            "-CAcreateserial",
            "-out", cert_path,
            "-days", "365",
            "-sha256"
        ], check=True)

        return FileResponse(cert_path, media_type="application/x-x509-user-cert")

    except subprocess.CalledProcessError as e:
        raise HTTPException(status_code=500, detail=f"OpenSSL error: {e}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Unexpected error: {e}")
    finally:
        csr.file.close()
        if os.path.exists(csr_path): os.remove(csr_path)


