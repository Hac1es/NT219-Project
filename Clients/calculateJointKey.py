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

    # Nhập đường dẫn đến public key trước đó (từ bank trước)
    prev_file = input("Input path to previous publicKey file: ").strip()
    if not os.path.exists(prev_file):
        raise Exception(f"File '{prev_file}' does not exist.")

    # Verify previous public key signature if it exists
    prev_sig_file = f"{prev_file}.sig"
    if os.path.exists(prev_sig_file):
        print("\nVerifying previous public key signature...")
        if not verify_file_signature(prev_file, signer):
            raise Exception("Previous public key signature verification failed")

    # 1. Thiết lập môi trường mã hóa CKKS
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

    # Serialize and sign public key
    pub_data = fhe.Serialize(keyPair.publicKey, fhe.BINARY)
    if not pub_data:
        raise Exception("Cannot serialize public key.")
    sign_and_save_file(pub_path, pub_data, signer)

    # Serialize and sign private key
    priv_data = fhe.Serialize(keyPair.secretKey, fhe.BINARY)
    if not priv_data:
        raise Exception("Cannot serialize private key.")
    sign_and_save_file(priv_path, priv_data, signer)

    # Verify the saved files
    print("\nVerifying saved key files...")
    verify_file_signature(pub_path, signer)
    verify_file_signature(priv_path, signer)

    print("\nKey pair generated and saved successfully!")
    print(f"Public Key: {pub_path}")
    print(f"Private Key: {priv_path}")
    print(f"Signatures: {pub_path}.sig and {priv_path}.sig")
