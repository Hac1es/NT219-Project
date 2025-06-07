from ecdsa import SigningKey, VerifyingKey, NIST256p
import hashlib
import json
import os
from typing import Union, Tuple

class ECDSASigner:
    def __init__(self, private_key_path: str = None, public_key_path: str = None):
        self.private_key_path = private_key_path
        self.public_key_path = public_key_path
        
        if private_key_path and os.path.exists(private_key_path):
            with open(private_key_path, 'rb') as f:
                self.private_key = SigningKey.from_pem(f.read())
                self.public_key = self.private_key.get_verifying_key()
        else:
            self.private_key = None
            self.public_key = None

    def sign(self, data: Union[str, bytes, dict], hashfunc=hashlib.sha256) -> bytes:
        if not self.private_key:
            raise ValueError("No private key available for signing")
            
        data_bytes = self._to_bytes(data)
        digest = hashfunc(data_bytes).digest()
        signature = self.private_key.sign_digest(digest)
        return signature

    def verify(self, data: Union[str, bytes, dict], signature: bytes, hashfunc=hashlib.sha256) -> bool:
        if not self.public_key:
            raise ValueError("No public key available for verification")
            
        data_bytes = self._to_bytes(data)
        digest = hashfunc(data_bytes).digest()
        try:
            return self.public_key.verify_digest(signature, digest)
        except:
            return False

    def export_private_key(self) -> bytes:
        if not self.private_key:
            raise ValueError("No private key available for export")
        return self.private_key.to_pem()

    def export_public_key(self) -> bytes:
        if not self.public_key:
            raise ValueError("No public key available for export")
        return self.public_key.to_pem()

    def save_keys(self, private_key_path: str = None, public_key_path: str = None) -> None:
        """Save the current keys to specified paths"""
        if not self.private_key or not self.public_key:
            raise ValueError("No keys available to save")

        private_key_path = private_key_path or self.private_key_path
        public_key_path = public_key_path or self.public_key_path

        if not private_key_path or not public_key_path:
            raise ValueError("Key paths must be specified")

        # Ensure directory exists
        os.makedirs(os.path.dirname(private_key_path), exist_ok=True)
        os.makedirs(os.path.dirname(public_key_path), exist_ok=True)

        # Save private key
        with open(private_key_path, 'wb') as f:
            f.write(self.export_private_key())

        # Save public key
        with open(public_key_path, 'wb') as f:
            f.write(self.export_public_key())

    @classmethod
    def generate_keys(cls, private_key_path: str, public_key_path: str) -> 'ECDSASigner':
        """Generate new key pair and save to specified paths"""
        # Generate new key pair
        private_key = SigningKey.generate(curve=NIST256p)
        public_key = private_key.get_verifying_key()

        # Create signer instance
        signer = cls()
        signer.private_key = private_key
        signer.public_key = public_key
        signer.private_key_path = private_key_path
        signer.public_key_path = public_key_path

        # Save keys
        signer.save_keys()

        return signer

    @staticmethod
    def load_private_key(pem_data: bytes) -> 'ECDSASigner':
        sk = SigningKey.from_pem(pem_data)
        return ECDSASigner(sk)

    @staticmethod
    def _to_bytes(data: Union[str, bytes, dict]) -> bytes:
        if isinstance(data, bytes):
            return data
        elif isinstance(data, str):
            return data.encode('utf-8')
        elif isinstance(data, dict):
            return json.dumps(data, sort_keys=True).encode('utf-8')
        else:
            raise TypeError("Unsupported data type for signing")

# Example usage:
if __name__ == "__main__":
    # Example paths
    PRIVATE_KEY_PATH = "keys/private_key.pem"
    PUBLIC_KEY_PATH = "keys/public_key.pem"

    # Generate new keys
    signer = ECDSASigner.generate_keys(PRIVATE_KEY_PATH, PUBLIC_KEY_PATH)
    
    # Or load existing keys
    # signer = ECDSASigner(PRIVATE_KEY_PATH, PUBLIC_KEY_PATH)
    
    # Example signing and verification
    data = {"message": "Hello, World!"}
    signature = signer.sign(data)
    is_valid = signer.verify(data, signature)
    print(f"Signature valid: {is_valid}")

