import os
import openfhe as fhe


def ensure_dir(path):
    if not os.path.exists(path):
        os.makedirs(path)

def save_file(file_path: str, data: bytes) -> None:
    """Sign the data and save both the data and its signature"""
    # Save the original data
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
