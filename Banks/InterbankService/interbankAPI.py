from fastapi import FastAPI, File, UploadFile, Form, HTTPException
from fastapi.responses import JSONResponse
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature
from cryptography import x509
import base64, json
from pathlib import Path
from datetime import datetime

app = FastAPI()
UPLOAD_DIR = Path("Received")
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

# Custom CA (Root CA) của bạn
CUSTOM_CA_PATH = "./RootCA.crt"

def verify_certificate_signed_by_root(cert: x509.Certificate, root_cert: x509.Certificate):
    try:
        # Lấy public key của RootCA
        root_pubkey = root_cert.public_key()
        # Verify cert được ký bởi RootCA
        root_pubkey.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            ec.ECDSA(cert.signature_hash_algorithm)
        )
        return True
    except Exception:
        return False

@app.post("/upload")
async def upload_file(
    file: UploadFile = File(...),
    certificate: UploadFile = File(...),
    signature: str = Form(...),
    metadata: str = Form(...)
):
    # Step 1: Đọc file và metadata
    try:
        file_bytes = await file.read()
        metadata_dict = json.loads(metadata)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid file or metadata.")

    # Step 2: Load cert và verify bằng RootCA
    try:
        cert_pem = await certificate.read()
        cert = x509.load_pem_x509_certificate(cert_pem)
        public_key = cert.public_key()

        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            raise HTTPException(status_code=400, detail="Certificate must use EC key.")

        with open(CUSTOM_CA_PATH, "rb") as f:
            root_cert_pem = f.read()
            root_cert = x509.load_pem_x509_certificate(root_cert_pem)

        if not verify_certificate_signed_by_root(cert, root_cert):
            raise HTTPException(status_code=403, detail="Certificate not signed by trusted RootCA.")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Certificate error: {e}")

    # Step 3: Verify chữ ký số
    try:
        data_to_verify = file_bytes + json.dumps(metadata_dict, sort_keys=True).encode("utf-8")
        decoded_sig = base64.b64decode(signature)

        public_key.verify(
            decoded_sig,
            data_to_verify,
            ec.ECDSA(hashes.SHA256())
        )
    except InvalidSignature:
        raise HTTPException(status_code=403, detail="Invalid signature.")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error verifying signature: {e}")

    # Step 4: Lưu file và metadata
    try:
        filename_base = f"{file.filename}"
        file_path = UPLOAD_DIR / filename_base
        metadata_path = file_path.with_suffix(".json")

        file_path.write_bytes(file_bytes)
        metadata_path.write_text(json.dumps(metadata_dict, indent=2))

        return JSONResponse(status_code=200, content={
            "message": "File received and verified.",
            "file_path": str(file_path),
            "metadata_path": str(metadata_path),
        })
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error saving file: {e}")
