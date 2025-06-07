import openfhe as fhe
import os

def generate_and_export_keys():
    """
    Generate and export cryptographic keys for homomorphic encryption using OpenFHE's CKKS scheme.
    This function creates a crypto context, generates key pairs, and serializes them to files.
    """
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

    # Create directory for storing the keys if it doesn't exist
    if not os.path.exists('keys'):
        os.makedirs('keys')

    # Generate the key pair (public and private keys)
    keys = crypto_context.KeyGen()
    # Generate evaluation key for multiplication operations
    # This key is needed for performing homomorphic multiplication
    crypto_context.EvalMultKeyGen(keys.secretKey)

    # Serialize the crypto context to a file
    # The crypto context contains all the parameters and settings needed for operations
    if not fhe.SerializeToFile('keys/cryptocontext.txt', crypto_context, fhe.BINARY):
        raise Exception("Error writing serialization of the crypto context")
    print("The cryptocontext has been serialized.")

    # Serialize the public key to a file
    # The public key is used for encryption and can be shared publicly
    if not fhe.SerializeToFile('keys/publicKey.txt', keys.publicKey, fhe.BINARY):
        raise Exception("Error writing serialization of the public key")
    print("The public key has been serialized.")

    # Serialize the private key to a file
    # The private key is used for decryption and must be kept secure
    if not fhe.SerializeToFile('keys/privateKey.txt', keys.secretKey, fhe.BINARY):
        raise Exception("Error writing serialization of the private key")
    print("The private key has been serialized.")

    # Serialize the evaluation multiplication key to a file
    # This key is needed for performing homomorphic multiplication operations
    if not crypto_context.SerializeEvalMultKey('keys/eval-mult-key.txt', fhe.BINARY):
        raise Exception("Error writing serialization of the eval mult key")
    print("The evaluation multiplication key has been serialized.")

    # Print summary of generated files
    print("\nKeys have been generated and exported to the 'keys' directory:")
    print("- cryptocontext.txt")  # Contains all parameters and settings
    print("- publicKey.txt")      # Used for encryption
    print("- privateKey.txt")     # Used for decryption
    print("- eval-mult-key.txt")  # Used for homomorphic multiplication

if __name__ == "__main__":
    generate_and_export_keys() 