import requests
import json
import base64
from getpass import getpass
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography import x509
from pathlib import Path

URL_MAPPER = {
    "MSB": "192.168.1.11",
    "ACB": "192.168.1.12"
}
BANK_CODE = "MSB"  # Mã ngân hàng của bạn
SERVER_URL = f"https://{URL_MAPPER[BANK_CODE]}/upload" 

# === INPUT FILE ===
file_path = input("Input file path: ").strip()
file_path = Path(file_path)
if not file_path.exists():
    print("File not exist.")
    exit(1)

# === OPTIONAL METADATA ===
metadata_input = input("Input Metadata (JSON): ").strip()
try:
    metadata = json.loads(metadata_input) if metadata_input else {}
except json.JSONDecodeError:
    print("Metadata not valid.")
    exit(1)

# === LOAD EC PRIVATE KEY ===
key_path = f"../Certificate/{BANK_CODE}.key"  
try:
    with open(key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
        )  
    if not isinstance(private_key, ec.EllipticCurvePrivateKey):
        raise TypeError("Wrong EC Key")
except Exception as e:
    print(f"Lỗi khi tải private key: {e}")
    exit(1)

# === TẠO CHỮ KÝ SỐ ===
try:
    with open(file_path, "rb") as f:
        file_bytes = f.read()
    data_to_sign = file_bytes + json.dumps(metadata, sort_keys=True).encode()

    signature = private_key.sign(
        data_to_sign,
        ec.ECDSA(hashes.SHA256())
    )
    signature_b64 = base64.b64encode(signature).decode()
except Exception as e:
    print(f"Lỗi khi tạo chữ ký số: {e}")
    exit(1)

# === LOAD X.509 CERT ===
cert_path = f"../Certificate/{BANK_CODE}.crt"
try:
    with open(cert_path, "rb") as f:
        cert_pem = f.read()
        cert_obj = x509.load_pem_x509_certificate(cert_pem)
except Exception as e:
    print(f"Lỗi khi đọc certificate: {e}")
    exit(1)

# === GỬI REQUEST ===
files = {
    "file": (file_path.name, file_bytes),
    "certificate": ("cert.pem", cert_pem),
}
data = {
    "metadata": json.dumps(metadata),
    "signature": signature_b64
}

try:
    print("Send request...")
    response = requests.post(SERVER_URL, data=data, files=files, verify="./RootCA.crt")
    print(f"✅ Server response({response.status_code}):\n{response.text}")
except Exception as e:
    print(f"Lỗi khi gửi HTTPS request: {e}")
