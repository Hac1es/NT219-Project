import os
import openfhe as fhe

def ensure_dir(path):
    if not os.path.exists(path):
        os.makedirs(path)

def save_file(file_path: str, data: bytes) -> None:
    """Save data to file"""
    # Save the original data
    with open(file_path, 'wb') as f:
        f.write(data)

if __name__ == "__main__":
    print("--- Participate in Joint Key Generation ---")
    print("--- Stage 1: Forward Accumulation ---")

    # Nhập tên ngân hàng
    bank_name = input("Input your bank code: ").strip()
    if not bank_name:
        raise Exception("Bank name cannot be empty.")

    key_dir = f'keys_{bank_name}'
    ensure_dir(key_dir)

    # Nhập đường dẫn đến private key
    prv_key_file = input("Input path to your privateKey file: ").strip()
    if not os.path.exists(prv_key_file):
        raise Exception(f"File '{prv_key_file}' does not exist.")

    # Thiết lập môi trường mã hóa CKKS
    parameters = fhe.CCParamsCKKSRNS()
    parameters.SetMultiplicativeDepth(15)
    parameters.SetScalingModSize(59)
    parameters.SetBatchSize(1)

    cc = fhe.GenCryptoContext(parameters)
    cc.Enable(fhe.PKESchemeFeature.PKE)
    cc.Enable(fhe.PKESchemeFeature.KEYSWITCH)
    cc.Enable(fhe.PKESchemeFeature.LEVELEDSHE)
    cc.Enable(fhe.PKESchemeFeature.ADVANCEDSHE)
    cc.Enable(fhe.PKESchemeFeature.MULTIPARTY)

    # Load private key
    print(f"Loading your private key from: {prv_key_file}")
    privateKey, result = fhe.DeserializePrivateKey(prv_key_file, fhe.BINARY)
    if not result:
        raise Exception("Cannot deserialize private key.")

    # Hỏi người dùng có phải người khởi tạo đầu tiên không
    is_starter = input("Are you the first party? (y/n): ").strip().lower()

    if is_starter == 'y':
        print("Generating initial EvalMultKey...")
        evalMulKey = cc.KeySwitchGen(privateKey, privateKey)
    else:
        # Load EvalMultKey trước đó từ file
        eval_key_file = input("Input path to previous EvalMultKey: ").strip()
        if not os.path.exists(eval_key_file):
            raise Exception(f"File '{eval_key_file}' does not exist.")
        
        with open(eval_key_file, 'rb') as f:
            eval_key_str = f.read()
        prev_eval_key = fhe.DeserializeEvalKeyString(eval_key_str, fhe.BINARY)
        if not isinstance(prev_eval_key, fhe.EvalKey):
            raise Exception("Invalid EvalKey type.")

        # Tạo phần khóa mới và tích lũy
        print("Generating EvalMultKey contribution...")
        newKeyPart = cc.MultiKeySwitchGen(privateKey, privateKey, prev_eval_key)

        print("Merging EvalMultKey parts...")
        evalMulKey = cc.MultiAddEvalKeys(prev_eval_key, newKeyPart, privateKey.GetKeyTag())

    # Serialize
    print("Serializing EvalMultKey...")
    eval_key_str = fhe.Serialize(evalMulKey, fhe.BINARY)
    eval_path = os.path.join(key_dir, "evalMultKey.txt")
    save_file(eval_path, eval_key_str)

    print(f"EvalMultKey part saved to: {eval_path}")
