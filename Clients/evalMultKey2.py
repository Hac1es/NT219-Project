import os
import openfhe as fhe

def ensure_dir(path):
    if not os.path.exists(path):
        os.makedirs(path)

def save_file(file_path: str, data: bytes) -> None:
    """Save the data"""
    # Save the original data
    with open(file_path, 'wb') as f:
        f.write(data)

if __name__ == "__main__":
    print("--- Participate in Joint Key Generation ---")
    print("--- Stage 2: Backward Finalization ---")

    # Nhập tên ngân hàng
    bank_name = input("Input your bank code: ").strip()
    if not bank_name:
        raise Exception("Bank name cannot be empty.")

    key_dir = f'keys_{bank_name}'
    ensure_dir(key_dir)

    # Đường dẫn đến EvalMultKey trước đó
    eval_key_file = input("Input path to current accumulated EvalMultKey file: ").strip()
    if not os.path.exists(eval_key_file):
        raise Exception(f"File '{eval_key_file}' does not exist.")

    # Đường dẫn đến PublicKey đã tích lũy
    joint_pub_key_file = input("Input path to joint public key file: ").strip()
    if not os.path.exists(joint_pub_key_file):
        raise Exception(f"File '{joint_pub_key_file}' does not exist.")

    # Đường dẫn đến private key cá nhân
    prv_key_file = input("Input path to your private key file: ").strip()
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

    # Load EvalMultKey tích lũy
    print(f"Loading EvalMultKey from: {eval_key_file}")
    with open(eval_key_file, 'rb') as f:
        eval_key_bytes = f.read()
    eval_key = fhe.DeserializeEvalKeyString(eval_key_bytes, fhe.BINARY)
    if not isinstance(eval_key, fhe.EvalKey):
        raise Exception("Invalid EvalKey type.")

    # Load public key chung
    print(f"Loading joint public key from: {joint_pub_key_file}")
    publicKey, result = fhe.DeserializePublicKey(joint_pub_key_file, fhe.BINARY)
    if not result:
        raise Exception("Cannot deserialize joint public key.")

    # Load private key cá nhân
    print(f"Loading private key from: {prv_key_file}")
    privateKey, result = fhe.DeserializePrivateKey(prv_key_file, fhe.BINARY)
    if not result:
        raise Exception("Cannot deserialize private key.")

    # Sinh phần EvalMultKey của riêng mình (backward)
    print("Generating backward EvalMultKey contribution...")
    finalKeyPart = cc.MultiMultEvalKey(privateKey, eval_key, publicKey.GetKeyTag())

    # Serialize
    eval_path = os.path.join(key_dir, "evalMultKey_final.txt")
    print("Serializing your EvalMultKey contribution...")
    eval_key_bytes = fhe.Serialize(finalKeyPart, fhe.BINARY)
    save_file(eval_path, eval_key_bytes)

    print(f"Final EvalMultKey contribution saved to: {eval_path}")

    # Hỏi người dùng có phải bên kết thúc không
    is_aggregator = input("Are you the aggregator party? (y/n): ").strip().lower()
    if is_aggregator == 'y':
        print("Now merging all final EvalMultKey parts...")

        num_parts = int(input("How many final EvalMultKey parts to merge?: "))
        final_keys = []

        for i in range(num_parts):
            path = input(f"Path to final EvalMultKey part #{i + 1}: ").strip()
            if not os.path.exists(path):
                raise Exception(f"File '{path}' does not exist.")
            
            with open(path, 'rb') as f:
                part_bytes = f.read()
            key_part = fhe.DeserializeEvalKeyString(part_bytes, fhe.BINARY)
            final_keys.append(key_part)

        # Gộp tuần tự
        merged_key = final_keys[0]
        for i in range(1, num_parts):
            merged_key = cc.MultiAddEvalMultKeys(merged_key, final_keys[i], merged_key.GetKeyTag())

        # Serialize and sign merged key
        merged_path = os.path.join(key_dir, "evalMultKey_merged.txt")
        print("Serializing merged EvalMultKey...")
        merged_bytes = fhe.Serialize(merged_key, fhe.BINARY)
        save_file(merged_path, merged_bytes)

        print(f"Final merged EvalMultKey saved to: {merged_path}")
