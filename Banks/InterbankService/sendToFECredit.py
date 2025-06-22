import requests
import json
import base64
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography import x509

# === CẤU HÌNH ===
URL_MAPPER = {
    "FECREDIT": "https://192.168.1.14:8000" # Sửa lại thành URL của server nhận
}
# Endpoint trên server nhận
API_ENDPOINT = "/calculate-credit-score"

# Danh sách các "key" của file mà server mong đợi
REQUIRED_FILE_KEYS = [
    'public_key',
    'eval_mult_key',
    'S_payment',
    'S_util',
    'S_length',
    'S_creditmix',
    'S_inquiries',
    'S_behavioral',
    'S_incomestability'
]

# === NHẬP THÔNG TIN CƠ BẢN ===
bank_code_sender = input("Enter your bank code: ").strip().upper()
SERVER_KEY = "FECREDIT" 
SERVER_URL = f"{URL_MAPPER[SERVER_KEY]}{API_ENDPOINT}"

# === NHẬP ĐƯỜNG DẪN CÁC FILE ===
print("\n--- Enter required filepath ---")
input_files = {}
for key in REQUIRED_FILE_KEYS:
    while True:
        file_path_str = input(f"File path for '{key}': ").strip()
        file_path = Path(file_path_str)
        if file_path.exists() and file_path.is_file():
            input_files[key] = file_path
            break
        else:
            print(f"File doesn't exists at '{file_path_str}'. Enter again")

# === OPTIONAL METADATA ===
metadata_input = input("\nEnter Metadata (JSON): ").strip()
try:
    metadata = json.loads(metadata_input) if metadata_input else {}
except json.JSONDecodeError:
    print("Lỗi: Metadata không phải là JSON hợp lệ.")
    exit(1)

# === LOAD EC PRIVATE KEY CỦA BÊN GỬI ===
key_path = f"../Certificate/{bank_code_sender}.key"  
try:
    with open(key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,  # Thêm password nếu key có mã hóa
        )
    if not isinstance(private_key, ec.EllipticCurvePrivateKey):
        raise TypeError("Key không phải là Elliptic Curve Private Key.")
except Exception as e:
    print(f"Lỗi khi tải private key từ '{key_path}': {e}")
    exit(1)

# === TẠO CHỮ KÝ SỐ ===
try:
    # 1. Đọc nội dung tất cả các file vào bộ nhớ
    file_contents = {}
    for key, path in input_files.items():
        with open(path, "rb") as f:
            file_contents[key] = f.read()

    # 2. Tạo dữ liệu để ký
    #    Rất quan trọng: Nối nội dung các file theo thứ tự key đã được sắp xếp
    #    để đảm bảo bên nhận có thể tái tạo lại đúng thứ tự để xác minh.
    data_to_sign = b''
    for key in sorted(file_contents.keys()):
        data_to_sign += file_contents[key]
    
    # 3. Nối metadata đã được chuẩn hóa vào cuối
    data_to_sign += json.dumps(metadata, sort_keys=True).encode('utf-8')

    # 4. Ký lên dữ liệu tổng hợp bằng private key
    signature = private_key.sign(
        data_to_sign,
        ec.ECDSA(hashes.SHA256())
    )
    signature_b64 = base64.b64encode(signature).decode('utf-8')
    print("\nCreate digital signature successful.")

except Exception as e:
    print(f"Lỗi khi tạo chữ ký số: {e}")
    exit(1)

# === LOAD X.509 CERTIFICATE CỦA BÊN GỬI ===
# Certificate này sẽ được gửi đi để bên nhận dùng public key trong đó để xác minh chữ ký
cert_path = f"../Certificate/{bank_code_sender}.crt"
try:
    with open(cert_path, "rb") as f:
        cert_pem_bytes = f.read()
except Exception as e:
    print(f"Lỗi khi đọc certificate từ '{cert_path}': {e}")
    exit(1)

# === CHUẨN BỊ VÀ GỬI REQUEST ===
# Chuẩn bị `files` dictionary cho requests
# Bao gồm tất cả các file dữ liệu VÀ file certificate của bên gửi
files_to_send = {
    # Thêm certificate vào danh sách file gửi đi
    "certificate": (f"{bank_code_sender}.crt", cert_pem_bytes, 'application/x-x509-ca-cert'),
}
for key, content in file_contents.items():
    # Sử dụng tên file gốc làm tên trong request
    original_filename = input_files[key].name
    files_to_send[key] = (original_filename, content, 'application/octet-stream')

# Chuẩn bị `data` dictionary cho requests (form data)
data_to_send = {
    "metadata": json.dumps(metadata),
    "signature": signature_b64
}

try:
    print(f"Sending request...")
    response = requests.post(SERVER_URL, data=data_to_send, files=files_to_send, verify="./RootCA.crt")
    
    print(f"Server response with status code: {response.status_code}")

    if response.status_code == 200:
        output_filename = 'Received/encryptedResult.txt'
        with open(output_filename, 'wb') as f:
            f.write(response.content)
        print(f"Result have been saved in '{output_filename}'")
    else:
        print("Yêu cầu thất bại. Chi tiết lỗi từ server:")
        print(response.text)

except requests.exceptions.RequestException as e:
    print(f"Lỗi nghiêm trọng khi gửi request: {e}")