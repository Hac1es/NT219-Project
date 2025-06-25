import requests
import json
import base64
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature
from requests_toolbelt.multipart import decoder
from base64 import b64decode

# === CẤU HÌNH ===
URL_MAPPER = {
    "FECREDIT": "https://192.168.1.14:8000" # Sửa lại thành URL của server nhận
}
# Endpoint trên server nhận
API_ENDPOINT = "/calculate-credit-score"

ROOT_CA_PATH = "./RootCA.crt" 

# Danh sách các "key" của file mà server mong đợi
REQUIRED_FILE_KEYS = [
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
    response = requests.post(SERVER_URL, data=data_to_send, files=files_to_send, verify="./RootCA.crt", timeout=(1000000, 3000000))
    
    print(f"Server response with status code: {response.status_code}")

    if response.status_code == 200:
        print("\n--- Verifying response from server ---")
        
        # 1. Parse multipart response
        try:
            multipart_data = {}
            # Dùng decoder để tách các part ra
            for part in decoder.MultipartDecoder.from_response(response).parts:
                # Lấy tên của part từ header 'Content-Disposition'
                disposition = part.headers[b'Content-Disposition'].decode()
                name = [p.split('=')[1].strip('"') for p in disposition.split(';') if 'name=' in p][0]
                multipart_data[name] = part.content # Lưu nội dung (bytes)

            # Lấy dữ liệu từ dict đã parse
            result_bytes = multipart_data['result_data']
            server_signature_bytes = multipart_data['server_signature']
            server_cert_pem_bytes = multipart_data['server_certificate']
            print("OK: Multipart response package parsed successfully.")
        except Exception as e:
            print(f"CRITICAL: Could not parse server's multipart response. Aborting. Error: {e}")
            exit(1)

        # 2. LỚP BẢO VỆ 1: Kiểm tra cert của server (logic không đổi)
        try:
            print("Step 1: Verifying server's certificate against RootCA...")
            with open(ROOT_CA_PATH, "rb") as f:
                root_cert = x509.load_pem_x509_certificate(f.read())
            
            server_cert = x509.load_pem_x509_certificate(server_cert_pem_bytes)
            
            root_cert.public_key().verify(
                server_cert.signature,
                server_cert.tbs_certificate_bytes,
                ec.ECDSA(server_cert.signature_hash_algorithm)
            )
            print("OK: Server's certificate is trusted.")
        except Exception as e:
            print(f"CRITICAL: Server's certificate cannot be trusted! Aborting. Reason: {e}")
            exit(1)
            
        # 3. LỚP BẢO VỆ 2: Kiểm tra chữ ký của server (logic không đổi)
        try:
            print("Step 2: Verifying server's signature on the result data...")
            server_public_key = server_cert.public_key()
            
            server_public_key.verify(
                server_signature_bytes, # Dùng trực tiếp bytes
                result_bytes,           # Dùng trực tiếp bytes
                ec.ECDSA(hashes.SHA256())
            )
            print("OK: Server's signature is valid. Response is authentic and integral.")
        except InvalidSignature:
            print("CRITICAL: Invalid signature from server! Response may have been tampered with. Aborting.")
            exit(1)
        except Exception as e:
            print(f"CRITICAL: An error occurred while verifying server signature. Aborting. Reason: {e}")
            exit(1)

        # 4. Chỉ khi TẤT CẢ đều OK, mới lưu file
        output_dir = Path("Received")
        output_dir.mkdir(exist_ok=True)
        output_filename = output_dir / 'encryptedResult.bin'
        
        with open(output_filename, 'wb') as f:
            f.write(result_bytes)
        print(f"\nSuccess! Verified result has been saved to '{output_filename}'")
        
    else:
        print("Request failed. Server error details:")
        print(response.text)


except requests.exceptions.RequestException as e:
    print(f"Lỗi nghiêm trọng khi gửi request: {e}")