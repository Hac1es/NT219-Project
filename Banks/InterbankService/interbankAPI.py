from fastapi import FastAPI, File, UploadFile, Form, HTTPException
from fastapi.responses import JSONResponse
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
from cryptography import x509
from certvalidator import CertificateValidator, ValidationContext
from asn1crypto import pem
import base64, json
from pathlib import Path
from datetime import datetime

app = FastAPI()
UPLOAD_DIR = Path("Received")
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

# Path tới CA bundle của hệ thống Linux
SYSTEM_CA_BUNDLE = "/etc/ssl/certs/ca-certificates.crt"

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

    # Step 2: Load certificate và verify chain-of-trust
    try:
        cert_pem = await certificate.read()

        # Chuyển sang DER nếu là PEM
        if pem.detect(cert_pem):
            _, _, cert_der = pem.unarmor(cert_pem)
        else:
            cert_der = cert_pem

        # Tạo context dùng CA hệ thống để verify chain-of-trust
        with open(SYSTEM_CA_BUNDLE, "rb") as f:
            trusted_ca = f.read()

        context = ValidationContext(trust_roots=[trusted_ca])
        validator = CertificateValidator(cert_der, validation_context=context)
        validator.validate_usage(set(["digital_signature"]))

        # Load lại thành cryptography.x509 để lấy public key
        cert = x509.load_pem_x509_certificate(cert_pem)
        public_key = cert.public_key()

        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            raise ValueError("Certificate must use EC key")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid certificate or trust validation failed: {e}")

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
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

        # Trích CN (Common Name) từ subject để làm định danh
        subject = cert.subject
        cn_attr = subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        bank_cn = cn_attr[0].value if cn_attr else "unknown"

        filename_base = f"{timestamp}_{bank_cn}_{file.filename}"
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
