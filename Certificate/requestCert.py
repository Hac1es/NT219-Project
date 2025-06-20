import subprocess
import requests
import tempfile
import os

# === 0. Hỏi người dùng nhập các trường cần thiết ===
print("=== Enter certificate information ===")
country = input("Country Name (2 letter code) [VN]: ")
state = input("State or Province Name [HCM]: ")
org = input("Organization Name [Maritime Bank]: ")

# === 1. Tạo Private Key và CSR ===
with tempfile.NamedTemporaryFile(suffix=".key", delete=False) as key_file, \
     tempfile.NamedTemporaryFile(suffix=".csr", delete=True) as csr_file:

    key_path = key_file.name
    csr_path = csr_file.name

    subprocess.run([
        "openssl", "ecparam", "-name", "prime256v1",
        "-genkey", "-noout", "-out", key_path
    ], check=True)

    # Ghép chuỗi subject từ input người dùng
    subject = f"/C={country}/ST={state}/L=ThuDuc/O={org}"

    subprocess.run([
        "openssl", "req", "-new", "-key", key_path,
        "-out", csr_path,
        "-subj", subject
    ], check=True)

# === 2. Gửi CSR qua HTTPS ===
with open(csr_path, "rb") as f:
    csr_data = f.read()
server_IP = input("Input server IP: ")
SERVER_URL = f"https://{server_IP}:8000"
CA_CERT = "rootCA.crt"
SAVE_DIR = "client_cert"
BANK_CODE = input("Input bank/organization code[ACB]: ")
response = requests.post(
    SERVER_URL,
    files={"csr": (f"{BANK_CODE}.csr", csr_data, "application/pkcs10")},
    verify=CA_CERT
)

if response.status_code == 200:
    client_key_path = f"{BANK_CODE}.key"
    client_crt_path = f"{BANK_CODE}.crt"

    with open(client_key_path, "wb") as f:
        f.write(open(key_path, "rb").read())

    with open(client_crt_path, "wb") as f:
        f.write(response.content)

    print(f"Certificate request complete!")
    print(f"Private key: {client_key_path}")
else:
    print(f"Certificate request failed: {response.status_code}")
    print(response.text)