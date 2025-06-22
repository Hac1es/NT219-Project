"""
File: evalMultKey2.py
Mô tả: Giai đoạn 2 của quá trình tạo khóa đánh giá phép nhân (EvalMultKey)
Chức năng chính:
- Giai đoạn 2: Hoàn thiện ngược (Backward Finalization)
- Tạo phần đóng góp cuối cùng cho EvalMultKey
- Hỗ trợ việc gộp các phần khóa từ nhiều bên
"""

import os
import openfhe as fhe

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
    print("--- Stage 2: Backward Finalization ---")

    # Nhập tên ngân hàng
    bank_name = "MSB"
    key_dir = 'Keys'

    # Nhập các đường dẫn file cần thiết
    eval_key_file = input("Input path to current accumulated EvalMultKey file: ").strip()
    if not os.path.exists(eval_key_file):
        raise Exception(f"File '{eval_key_file}' does not exist.")

    joint_pub_key_file = input("Input path to joint public key file: ").strip()
    if not os.path.exists(joint_pub_key_file):
        raise Exception(f"File '{joint_pub_key_file}' does not exist.")

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

    # Tải EvalMultKey đã tích lũy
    print(f"Loading EvalMultKey from: {eval_key_file}")
    with open(eval_key_file, 'rb') as f:
        eval_key_bytes = f.read()
    eval_key = fhe.DeserializeEvalKeyString(eval_key_bytes, fhe.BINARY)
    if not isinstance(eval_key, fhe.EvalKey):
        raise Exception("Invalid EvalKey type.")

    # Tải khóa công khai chung
    print(f"Loading joint public key from: {joint_pub_key_file}")
    publicKey, result = fhe.DeserializePublicKey(joint_pub_key_file, fhe.BINARY)
    if not result:
        raise Exception("Cannot deserialize joint public key.")

    # Tải khóa riêng tư cá nhân
    print(f"Loading private key from: {prv_key_file}")
    privateKey, result = fhe.DeserializePrivateKey(prv_key_file, fhe.BINARY)
    if not result:
        raise Exception("Cannot deserialize private key.")

    # Tạo phần đóng góp EvalMultKey cuối cùng (ngược)
    print("Generating backward EvalMultKey contribution...")
    finalKeyPart = cc.MultiMultEvalKey(privateKey, eval_key, publicKey.GetKeyTag())

    # Lưu phần đóng góp vào file
    eval_path = os.path.join(key_dir, "evalMultKey_final.txt")
    print("Serializing your EvalMultKey contribution...")
    eval_key_bytes = fhe.Serialize(finalKeyPart, fhe.BINARY)
    save_file(eval_path, eval_key_bytes)

    print(f"Final EvalMultKey contribution saved to: {eval_path}")

    # Xác định xem có phải bên tổng hợp không
    is_aggregator = input("Are you the aggregator party? (y/n): ").strip().lower()
    if is_aggregator == 'y':
        print("Now merging all final EvalMultKey parts...")

        # Nhập số lượng phần khóa cần gộp
        num_parts = int(input("How many final EvalMultKey parts to merge?: "))
        final_keys = []

        # Tải từng phần khóa
        for i in range(num_parts):
            path = input(f"Path to final EvalMultKey part #{i + 1}: ").strip()
            if not os.path.exists(path):
                raise Exception(f"File '{path}' does not exist.")
            
            with open(path, 'rb') as f:
                part_bytes = f.read()
            key_part = fhe.DeserializeEvalKeyString(part_bytes, fhe.BINARY)
            final_keys.append(key_part)

        # Gộp tuần tự các phần khóa
        merged_key = final_keys[0]
        for i in range(1, num_parts):
            merged_key = cc.MultiAddEvalMultKeys(merged_key, final_keys[i], merged_key.GetKeyTag())

        # Lưu khóa đã gộp
        merged_path = os.path.join(key_dir, "evalMultKey_merged.txt")
        print("Serializing merged EvalMultKey...")
        merged_bytes = fhe.Serialize(merged_key, fhe.BINARY)
        save_file(merged_path, merged_bytes)

        print(f"Final merged EvalMultKey saved to: {merged_path}")
