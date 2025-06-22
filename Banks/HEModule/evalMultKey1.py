"""
File: evalMultKey1.py
Mô tả: Tạo khóa đánh giá phép nhân (EvalMultKey) cho mã hóa đồng hình
Chức năng chính:
- Giai đoạn 1: Tích lũy tiến (Forward Accumulation)
- Tạo khóa đánh giá phép nhân cho một bên hoặc nhiều bên
- Hỗ trợ quá trình tạo khóa chung giữa các ngân hàng
"""

import os
import openfhe as fhe

bank_name = "MSB"

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
    print(f"--- {bank_name} Participate in Joint Key Generation ---")
    print("--- Stage 1: Forward Accumulation ---")
    key_dir = 'Keys'

    # Nhập đường dẫn đến private key
    prv_key_file = input("Input path to your privateKey file: ").strip()
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

    # Tải khóa riêng tư
    print(f"Loading your private key from: {prv_key_file}")
    privateKey, result = fhe.DeserializePrivateKey(prv_key_file, fhe.BINARY)
    if not result:
        raise Exception("Cannot deserialize private key.")

    # Xác định xem có phải bên khởi tạo đầu tiên không
    is_starter = input("Are you the first party? (y/n): ").strip().lower()

    if is_starter == 'y':
        # Nếu là bên đầu tiên, tạo EvalMultKey ban đầu
        print("Generating initial EvalMultKey...")
        evalMulKey = cc.KeySwitchGen(privateKey, privateKey)
    else:
        # Nếu không phải bên đầu tiên, tải EvalMultKey trước đó và thêm phần đóng góp
        eval_key_file = input("Input path to previous EvalMultKey: ").strip()
        if not os.path.exists(eval_key_file):
            raise Exception(f"File '{eval_key_file}' does not exist.")
        
        # Tải và kiểm tra EvalMultKey trước đó
        with open(eval_key_file, 'rb') as f:
            eval_key_str = f.read()
        prev_eval_key = fhe.DeserializeEvalKeyString(eval_key_str, fhe.BINARY)
        if not isinstance(prev_eval_key, fhe.EvalKey):
            raise Exception("Invalid EvalKey type.")

        # Tạo phần khóa mới và tích lũy
        print("Generating EvalMultKey contribution...")
        newKeyPart = cc.MultiKeySwitchGen(privateKey, privateKey, prev_eval_key)

        # Kết hợp các phần khóa
        print("Merging EvalMultKey parts...")
        evalMulKey = cc.MultiAddEvalKeys(prev_eval_key, newKeyPart, privateKey.GetKeyTag())

    # Lưu EvalMultKey vào file
    print("Serializing EvalMultKey...")
    eval_key_str = fhe.Serialize(evalMulKey, fhe.BINARY)
    eval_path = os.path.join(key_dir, "evalMultKey.txt")
    save_file(eval_path, eval_key_str)

    print(f"EvalMultKey part saved to: {eval_path}")
