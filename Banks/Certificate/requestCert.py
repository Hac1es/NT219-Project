import subprocess
import requests
import tempfile
import os

country = "VN"
state = "Ho Chi Minh"
org = "A Chau Bank"
commonname = "ACB"
public_ip = "192.168.1.12"
server_domain = "www.sbv.org"

# === 1. Tạo file config tạm có SAN ===
with tempfile.NamedTemporaryFile("w", suffix=".cnf", delete=False) as config_file:
    config_path = config_file.name
    config_file.write(f"""
[req]
default_bits       = 2048
distinguished_name = req_distinguished_name
req_extensions     = req_ext
prompt             = no

[req_distinguished_name]
C = {country}
ST = {state}
O = {org}
CN = {commonname}

[req_ext]
subjectAltName = IP:{public_ip}
""")

# === 2. Tạo file tạm cho key và CSR, rồi đóng lại để openssl dùng được ===
key_file = tempfile.NamedTemporaryFile(suffix=".key", delete=False)
csr_file = tempfile.NamedTemporaryFile(suffix=".csr", delete=False)
key_path = key_file.name
csr_path = csr_file.name
key_file.close()
csr_file.close()

# === 3. Tạo EC Private Key ===
subprocess.run([
    "openssl", "ecparam", "-name", "prime256v1",
    "-genkey", "-noout", "-out", key_path
], check=True)

# === 4. Tạo CSR từ private key + config ===
subprocess.run([
    "openssl", "req", "-new", "-key", key_path,
    "-out", csr_path,
    "-config", config_path
], check=True)

# === 5. Gửi CSR qua HTTPS ===
with open(csr_path, "rb") as f:
    csr_data = f.read()
SERVER_URL = f"https://{server_domain}:443/submit-csr"
response = requests.post(
    SERVER_URL,
    files={"csr": (f"{commonname}.csr", csr_data, "application/pkcs10")},
    verify="./RootCA.crt"
)

# === 6. Nhận và lưu cert nếu thành công ===
if response.status_code == 200:
    client_key_path = f"{commonname}.key"
    client_crt_path = f"{commonname}.crt"

    with open(client_key_path, "wb") as f:
        f.write(open(key_path, "rb").read())

    with open(client_crt_path, "wb") as f:
        f.write(response.content)

    print(f"Certificate request complete!")
    print(f"Private key: {client_key_path}")
    print(f"Certificate: {client_crt_path}")
else:
    print(f"Certificate request failed: {response.status_code}")
    print(response.text)

# === 7. Cleanup ===
os.remove(csr_path)
os.remove(config_path)
