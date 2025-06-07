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
    print("--- Stage 1: Forward Accumulation ---")

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

    # Nhập đường dẫn đến private key
    prv_key_file = input("Input path to your privateKey file: ").strip()
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
        
        # Verify previous EvalMultKey signature if it exists
        eval_sig_file = f"{eval_key_file}.sig"
        if os.path.exists(eval_sig_file):
            print("\nVerifying previous EvalMultKey signature...")
            if not verify_file_signature(eval_key_file, signer):
                raise Exception("Previous EvalMultKey signature verification failed")
        
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

    # Serialize and sign
    print("Serializing and signing EvalMultKey...")
    eval_key_str = fhe.Serialize(evalMulKey, fhe.BINARY)
    eval_path = os.path.join(key_dir, "evalMultKey.txt")
    sign_and_save_file(eval_path, eval_key_str, signer)

    # Verify the saved file
    print("\nVerifying saved EvalMultKey...")
    verify_file_signature(eval_path, signer)

    print(f"EvalMultKey part saved to: {eval_path}")
    print(f"Signature saved to: {eval_path}.sig")
