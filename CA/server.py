from fastapi import FastAPI, File, UploadFile, HTTPException, Request, Form
from fastapi.responses import FileResponse
import subprocess
import tempfile
import shutil
import os

app = FastAPI()

# Danh sách IP cho phép: MSB, ACB, FECREDIT
ALLOWED_IPS = {"192.168.1.11", "192.168.1.12", "192.168.1.14"}  

@app.middleware("http")
async def verify_client_ip(request: Request, call_next):
    client_ip = request.client.host
    if client_ip not in ALLOWED_IPS:
        raise HTTPException(status_code=403, detail="Forbidden: IP not allowed")
    response = await call_next(request)
    return response

@app.post("/submit-csr")
async def handle_csr(csr: UploadFile = File(...),
    config: UploadFile = File(...)):
    try:
        # Lưu CSR tạm
        with tempfile.NamedTemporaryFile(suffix=".csr", delete=False) as csr_file:
            csr_path = csr_file.name
            shutil.copyfileobj(csr.file, csr_file)

        # Lưu config file tạm (dùng để ký có SAN)
        with tempfile.NamedTemporaryFile(suffix=".cnf", delete=False) as config_file:
            config_path = config_file.name
            shutil.copyfileobj(config.file, config_file)

        # Tạo cert tạm
        with tempfile.NamedTemporaryFile(suffix=".crt", delete=False) as cert_file:
            cert_path = cert_file.name

        # Ký CSR bằng config chứa SAN
        subprocess.run([
            "openssl", "x509", "-req",
            "-in", csr_path,
            "-CA", "rootCA.crt",
            "-CAkey", "rootCA.key",
            "-CAcreateserial",
            "-out", cert_path,
            "-days", "365",
            "-sha256",
            "-extfile", config_path,
            "-extensions", "req_ext"
        ], check=True)

        return FileResponse(cert_path, media_type="application/x-x509-user-cert")
    except subprocess.CalledProcessError as e:
        raise HTTPException(status_code=500, detail=f"OpenSSL error: {e}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Unexpected error: {e}")
    finally:
        csr.file.close()
        if os.path.exists(csr_path): os.remove(csr_path)
        if os.path.exists("sbvCert.srl"): os.remove("sbvCert.srl")


