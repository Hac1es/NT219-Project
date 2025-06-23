import subprocess
import requests
import tempfile
import os

country = "VN"
state = "Ho Chi Minh"
org = "FE Credit"
commonname = "FECREDIT"

# === 1. Tạo Private Key và CSR ===
with tempfile.NamedTemporaryFile(suffix=".key", delete=False) as key_file, \
     tempfile.NamedTemporaryFile(suffix=".csr", delete=False) as csr_file:

    key_path = key_file.name
    csr_path = csr_file.name

    subprocess.run([
        "openssl", "ecparam", "-name", "prime256v1",
        "-genkey", "-noout", "-out", key_path
    ], check=True)

    # Ghép chuỗi subject từ input người dùng
    subject = f"/C={country}/ST={state}/O={org}/CN={commonname}"

    subprocess.run([
        "openssl", "req", "-new", "-key", key_path,
        "-out", csr_path,
        "-subj", subject
    ], check=True)

# === 2. Gửi CSR qua HTTPS ===
with open(csr_path, "rb") as f:
    csr_data = f.read()
server_IP = input("Input server IP: ")
SERVER_URL = f"https://{server_IP}:443/submit-csr"
response = requests.post(
    SERVER_URL,
    files={"csr": (f"{commonname}.csr", csr_data, "application/pkcs10")},
    verify="./RootCA.crt",
    timeout=(10, 300)
)

if response.status_code == 200:
    client_key_path = f"{commonname}.key"
    client_crt_path = f"{commonname}.crt"

    with open(client_key_path, "wb") as f:
        f.write(open(key_path, "rb").read())

    with open(client_crt_path, "wb") as f:
        f.write(response.content)

    print(f"Certificate request complete!")
    print(f"Private key: {client_key_path}")
    os.remove(csr_path)
else:
    print(f"Certificate request failed: {response.status_code}")
    print(response.text)
    os.remove(csr_path)