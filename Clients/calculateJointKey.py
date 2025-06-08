"""
File: calculateJointKey.py
Mô tả: Tham gia quá trình tạo khóa công khai chung giữa các ngân hàng (Multiparty Public Key Generation)
Chức năng chính:
- Nhận public key từ ngân hàng trước đó
- Sinh đóng góp mới vào public key chung
- Lưu lại cặp khóa mới (public/private) cho ngân hàng hiện tại
"""

import os
import openfhe as fhe


def ensure_dir(path):
    """
    Hàm tạo thư mục nếu chưa tồn tại
    Args:
        path: Đường dẫn thư mục cần tạo
    """
    if not os.path.exists(path):
        os.makedirs(path)

def save_file(file_path: str, data: bytes) -> None:
    """
    Lưu dữ liệu vào file
    Args:
        file_path: Đường dẫn file cần lưu
        data: Dữ liệu dạng bytes cần lưu
    """
    with open(file_path, 'wb') as f:
        f.write(data)

if __name__ == "__main__":
    print("--- Participate in Joint Key Generation ---")
    
    # Nhập tên ngân hàng
    bank_name = input("Input your bank code: ").strip()
    if not bank_name:
        raise Exception("Bank name cannot be empty.")

    key_dir = f'keys_{bank_name}'
    ensure_dir(key_dir)

    # Nhập đường dẫn đến public key trước đó (từ bank trước)
    prev_file = input("Input path to previous publicKey file: ").strip()
    if not os.path.exists(prev_file):
        raise Exception(f"File '{prev_file}' does not exist.")

    # 1. Thiết lập môi trường mã hóa CKKS
    parameters = fhe.CCParamsCKKSRNS()
    parameters.SetMultiplicativeDepth(15)  # Độ sâu tối đa cho phép nhân
    parameters.SetScalingModSize(59)       # Kích thước hệ số tỷ lệ
    parameters.SetBatchSize(1)             # Số lượng slot xử lý hàng loạt

    # Khởi tạo context mã hóa và bật các tính năng cần thiết
    cc = fhe.GenCryptoContext(parameters)
    cc.Enable(fhe.PKESchemeFeature.PKE)           # Mã hóa công khai cơ bản
    cc.Enable(fhe.PKESchemeFeature.KEYSWITCH)     # Chuyển đổi khóa
    cc.Enable(fhe.PKESchemeFeature.LEVELEDSHE)    # Mã hóa đồng hình có cấp độ
    cc.Enable(fhe.PKESchemeFeature.ADVANCEDSHE)   # Mã hóa đồng hình nâng cao
    cc.Enable(fhe.PKESchemeFeature.MULTIPARTY)    # Hỗ trợ nhiều bên

    # 2. Deserialize publicKey của bên trước
    print(f"Loading public key from: {prev_file}")
    publicKey, result = fhe.DeserializePublicKey(prev_file, fhe.BINARY)
    if not result:
        raise Exception("Cannot deserialize previous public key.")

    # 3. Tạo cặp khóa mới dựa trên publicKey trước đó
    print("Generating contribution to joint public key...")
    keyPair = cc.MultipartyKeyGen(publicKey)

    # 4. Lưu lại public key và secret key mới (có ký)
    pub_path = os.path.join(key_dir, f"{bank_name}_publicKey.txt")
    priv_path = os.path.join(key_dir, f"{bank_name}_privateKey.txt")

    # Serialize public key
    pub_data = fhe.Serialize(keyPair.publicKey, fhe.BINARY)
    if not pub_data:
        raise Exception("Cannot serialize public key.")
    save_file(pub_path, pub_data)

    # Serialize private key
    priv_data = fhe.Serialize(keyPair.secretKey, fhe.BINARY)
    if not priv_data:
        raise Exception("Cannot serialize private key.")
    save_file(priv_path, priv_data)

    print("\nKey pair generated and saved successfully!")
    print(f"Public Key: {pub_path}")
    print(f"Private Key: {priv_path}")
