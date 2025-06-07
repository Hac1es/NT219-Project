import os
import openfhe as fhe
from signingModule import ECDSASigner

PRIVATE_KEY_PATH = "ecdsa_private.pem"
PUBLIC_KEY_PATH = "ecdsa_public.pem"

def ensure_dir(path):
    if not os.path.exists(path):
        os.makedirs(path)

def sign_and_save_file(file_path: str, data: bytes, signer: ECDSASigner) -> None:
    """Sign the data and save both the data and its signature"""
    # Save the original data
    with open(file_path, 'wb') as f:
        f.write(data)
    
    # Generate and save signature
    signature = signer.sign(data)
    sig_path = f"{file_path}.sig"
    with open(sig_path, 'wb') as f:
        f.write(signature)
    
    print(f"Saved signed file: {file_path}")
    print(f"Saved signature: {sig_path}")

def verify_file_signature(file_path: str, signer: ECDSASigner) -> bool:
    """Verify the signature of a file"""
    if not os.path.exists(file_path):
        print(f"Error: File {file_path} does not exist")
        return False
        
    sig_path = f"{file_path}.sig"
    if not os.path.exists(sig_path):
        print(f"Error: Signature file {sig_path} does not exist")
        return False

    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        with open(sig_path, 'rb') as f:
            signature = f.read()
            
        is_valid = signer.verify(data, signature)
        if is_valid:
            print(f"✓ Signature valid for {file_path}")
        else:
            print(f"✗ Invalid signature for {file_path}")
        return is_valid
    except Exception as e:
        print(f"Error verifying {file_path}: {str(e)}")
        return False

if __name__ == "__main__":
    print("--- Participate in Joint Key Generation ---")
    print("--- Stage 2: Backward Finalization ---")

    # Initialize ECDSA signer
    if not os.path.exists(PRIVATE_KEY_PATH):
        print("Generating new ECDSA key pair...")
        signer = ECDSASigner.generate_keys(PRIVATE_KEY_PATH, PUBLIC_KEY_PATH)
    else:
        print("Loading existing ECDSA key pair...")
        signer = ECDSASigner(PRIVATE_KEY_PATH, PUBLIC_KEY_PATH)

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

    # Verify EvalMultKey signature if it exists
    eval_sig_file = f"{eval_key_file}.sig"
    if os.path.exists(eval_sig_file):
        print("\nVerifying EvalMultKey signature...")
        if not verify_file_signature(eval_key_file, signer):
            raise Exception("EvalMultKey signature verification failed")

    # Đường dẫn đến PublicKey đã tích lũy
    joint_pub_key_file = input("Input path to joint public key file: ").strip()
    if not os.path.exists(joint_pub_key_file):
        raise Exception(f"File '{joint_pub_key_file}' does not exist.")

    # Verify joint public key signature if it exists
    pub_sig_file = f"{joint_pub_key_file}.sig"
    if os.path.exists(pub_sig_file):
        print("\nVerifying joint public key signature...")
        if not verify_file_signature(joint_pub_key_file, signer):
            raise Exception("Joint public key signature verification failed")

    # Đường dẫn đến private key cá nhân
    prv_key_file = input("Input path to your private key file: ").strip()
    if not os.path.exists(prv_key_file):
        raise Exception(f"File '{prv_key_file}' does not exist.")

    # Verify private key signature if it exists
    prv_sig_file = f"{prv_key_file}.sig"
    if os.path.exists(prv_sig_file):
        print("\nVerifying private key signature...")
        if not verify_file_signature(prv_key_file, signer):
            raise Exception("Private key signature verification failed")

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

    # Serialize and sign
    eval_path = os.path.join(key_dir, "evalMultKey_final.txt")
    print("Serializing and signing your EvalMultKey contribution...")
    eval_key_bytes = fhe.Serialize(finalKeyPart, fhe.BINARY)
    sign_and_save_file(eval_path, eval_key_bytes, signer)

    # Verify the saved file
    print("\nVerifying saved EvalMultKey contribution...")
    verify_file_signature(eval_path, signer)

    print(f"Final EvalMultKey contribution saved to: {eval_path}")
    print(f"Signature saved to: {eval_path}.sig")

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
            
            # Verify each part's signature if it exists
            part_sig_file = f"{path}.sig"
            if os.path.exists(part_sig_file):
                print(f"\nVerifying signature for part #{i + 1}...")
                if not verify_file_signature(path, signer):
                    raise Exception(f"Signature verification failed for part #{i + 1}")
            
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
        print("Serializing and signing merged EvalMultKey...")
        merged_bytes = fhe.Serialize(merged_key, fhe.BINARY)
        sign_and_save_file(merged_path, merged_bytes, signer)

        # Verify the merged key
        print("\nVerifying merged EvalMultKey...")
        verify_file_signature(merged_path, signer)

        print(f"Final merged EvalMultKey saved to: {merged_path}")
        print(f"Signature saved to: {merged_path}.sig")
