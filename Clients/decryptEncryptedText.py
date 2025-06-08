"""
File: decryptEncryptedText.py
Mô tả: Tham gia quá trình giải mã kết quả mã hóa liên ngân hàng
Chức năng chính:
- Giải mã từng phần ciphertext bằng private key của từng ngân hàng
- Lưu phần giải mã cục bộ
- Nếu là bên tổng hợp, ghép các phần giải mã để lấy kết quả cuối cùng
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

if __name__ == "__main__":
    print("--- Participate in Decrypt Result ---")

    # Nhập tên ngân hàng
    bank_name = input("Input your bank code: ").strip()
    if not bank_name:
        raise Exception("Bank name cannot be empty.")

    key_dir = f'keys_{bank_name}'
    ensure_dir(key_dir)

    # Đường dẫn đến private key cá nhân
    prv_key_file = input("Input path to your private key file: ").strip()
    if not os.path.exists(prv_key_file):
        raise Exception(f"File '{prv_key_file}' does not exist.")

    # Thiết lập môi trường mã hóa CKKS
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

    # Tải private key
    privateKey, result = fhe.DeserializePrivateKey(prv_key_file, fhe.BINARY)
    if not result:
        raise Exception("Cannot deserialize private key.")

    # === Giải mã kết quả mã hóa liên ngân hàng ===
    encrypted_file = input("Path to the encrypted result file: ").strip()
    if not os.path.exists(encrypted_file):
        raise Exception(f"Encrypted file '{encrypted_file}' does not exist.")
    with open(encrypted_file, 'rb') as f:
        ct_bytes = f.read()
    encrypted_result, result = fhe.DeserializeCiphertext(ct_bytes, fhe.BINARY)
    if not result:
        raise Exception(
            "Error reading serialization of the joint ciphertext"
        )
    print("The joint ciphertext has been deserialized.")


    # Hỏi người dùng là Lead hay Main
    role = input("Are you the 'lead' party for decryption? (y/n): ").strip().lower()
    if role == 'y':
        part_decrypt = cc.MultipartyDecryptLead([encrypted_result], privateKey)[0]
    else:
        part_decrypt = cc.MultipartyDecryptMain([encrypted_result], privateKey)[0]

    # Lưu phần giải mã cục bộ của bạn
    part_dec_path = os.path.join(key_dir, "partial_decryption.txt")
    with open(part_dec_path, 'wb') as f:
        f.write(fhe.Serialize(part_decrypt, fhe.BINARY))
    print(f"Your partial decryption saved to: {part_dec_path}")

    # Hỏi người dùng có phải bên tập hợp kết quả không
    is_aggregator = input("Are you the aggregator party? (y/n): ").strip().lower()
    if is_aggregator == 'y':
        print("Merging all partial decryptions...")
        num_parts = int(input("How many partial decryptions to merge?: "))
        part_decryptions = []

        for i in range(num_parts):
            path = input(f"Path to partial decryption #{i + 1}: ").strip()
            if not os.path.exists(path):
                raise Exception(f"File '{path}' does not exist.")
            part_ct = fhe.DeserializeCiphertext(path, fhe.BINARY)
            part_decryptions.append(part_ct)

        # Ghép các phần giải mã lại
        result_ptxt = cc.MultipartyDecryptFusion(part_decryptions)
        result_ptxt.SetLength(1)  # chỉ giải mã một giá trị duy nhất
        # Trả về kết quả thang 300 - 850
        raw_score = result_ptxt.GetRealPackedValue()[0]
        credit_score = 300 + (raw_score * 550)
        print("\n=== Final Decryption Result ===")
        print("Decrypted value:", raw_score)