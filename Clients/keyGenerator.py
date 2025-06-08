"""
File: keyGenerator.py
Mô tả: Tạo và xuất khóa mã hóa đồng hình (homomorphic encryption) cho các ngân hàng
Chức năng chính:
- Tạo cặp khóa công khai và riêng tư sử dụng OpenFHE CKKS
- Lưu trữ khóa vào thư mục riêng cho từng ngân hàng
- Hỗ trợ mã hóa số thực và các phép tính xấp xỉ
"""

import openfhe as fhe
import os

def ensure_dir(path):
    """
    Hàm tạo thư mục nếu chưa tồn tại
    Args:
        path: Đường dẫn thư mục cần tạo
    """
    if not os.path.exists(path):
        os.makedirs(path)

def generate_and_export_keys():
    """
    Tạo và xuất khóa mã hóa đồng hình sử dụng OpenFHE CKKS
    - Tạo context mã hóa
    - Tạo cặp khóa
    - Xuất khóa ra file
    """
     # Nhập tên ngân hàng
    bank_name = input("Input your bank code: ").strip()
    if not bank_name:
        raise Exception("Bank name cannot be empty.")
    
    key_dir = f'keys_{bank_name}'
    ensure_dir(key_dir)
    
    # Initialize CKKS parameters
    # CKKS is a scheme that supports approximate arithmetic on encrypted real numbers
    parameters = fhe.CCParamsCKKSRNS()
    # Set the maximum depth of multiplication operations allowed
    parameters.SetMultiplicativeDepth(15)
    # Set the scaling factor size for CKKS encoding
    parameters.SetScalingModSize(59)
    # Set the number of slots for batch processing
    parameters.SetBatchSize(1)

    # Create crypto context with the specified parameters
    # The crypto context manages all cryptographic operations
    crypto_context = fhe.GenCryptoContext(parameters)
    
    # Enable required features for the crypto context
    # PKE: Public Key Encryption - enables basic encryption/decryption
    crypto_context.Enable(fhe.PKESchemeFeature.PKE)
    # LEVELEDSHE: Leveled Homomorphic Encryption - enables operations with limited depth
    crypto_context.Enable(fhe.PKESchemeFeature.LEVELEDSHE)
    # ADVANCEDSHE: Advanced Homomorphic Encryption - enables more complex operations
    crypto_context.Enable(fhe.PKESchemeFeature.ADVANCEDSHE)
    crypto_context.Enable(fhe.PKESchemeFeature.MULTIPARTY)

    # Generate the key pair (public and private keys)
    keys = crypto_context.KeyGen()


    # Serialize the public key to a file
    # The public key is used for encryption and can be shared publicly
    if not fhe.SerializeToFile(f'{key_dir}/{bank_name}_publicKey.txt', keys.publicKey, fhe.BINARY):
        raise Exception("Error writing serialization of the public key")
    print("The public key has been serialized.")

    # Serialize the private key to a file
    # The private key is used for decryption and must be kept secure
    if not fhe.SerializeToFile(f'{key_dir}/{bank_name}_privateKey.txt', keys.secretKey, fhe.BINARY):
        raise Exception("Error writing serialization of the private key")
    print("The private key has been serialized.")

    # Print summary of generated files
    print("\nKeys have been generated and exported:")
    print("- publicKey.txt")      # Used for encryption
    print("- privateKey.txt")     # Used for decryption

if __name__ == "__main__":
    generate_and_export_keys() 