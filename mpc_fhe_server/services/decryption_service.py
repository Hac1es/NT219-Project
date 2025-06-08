import numpy as np
import json
from ..core.crypto_context import CryptoContextManager
from ..core.serialization import serialize_to_file, deserialize_from_file
from ..core.storage import StorageManager
from ..config.config import MIN_SCORE, MAX_SCORE, RESULT_FOLDER, PARTIAL_DECRYPTION_FOLDER
import os

class DecryptionService:
    def __init__(self):
        self.cc_manager = CryptoContextManager()
        self.cc = self.cc_manager.get_context()
        self.partial_decryptions = {}
    
    def create_partial_decryption(self, bank, is_lead=False):
        """Create a partial decryption for a bank"""
        if not bank.keys:
            return None, "Bank keys not found"
            
        # Get the encrypted result
        from .computation_service import ComputationService
        comp_service = ComputationService()
        encrypted_result, error = comp_service.get_encrypted_result()
        
        if error:
            return None, error
            
        # Create partial decryption
        try:
            if is_lead:
                partial = self.cc.MultipartyDecryptLead([encrypted_result], bank.keys.secretKey)[0]
            else:
                partial = self.cc.MultipartyDecryptMain([encrypted_result], bank.keys.secretKey)[0]
                
            # Save partial decryption
            partial_path = f"{PARTIAL_DECRYPTION_FOLDER}/{bank.bank_code}_partial.bin"
            serialize_to_file(partial, partial_path)
            
            # Store in memory
            self.partial_decryptions[bank.bank_code] = partial
            bank.set_partial_decrypt(partial)
            
            return partial, None
        except Exception as e:
            return None, str(e)
    
    def submit_partial_decryption_file(self, bank_code, file_data):
        """Submit a pre-created partial decryption file"""
        # Save the file
        partial_path = f"{PARTIAL_DECRYPTION_FOLDER}/{bank_code}_partial.bin"
        with open(partial_path, 'wb') as f:
            f.write(file_data)
            
        # Load into memory
        partial, success = deserialize_from_file(partial_path, "ciphertext")
        
        if not success:
            return None, "Failed to deserialize partial decryption"
            
        self.partial_decryptions[bank_code] = partial
        return partial, None
    
    def finalize_decryption(self, banks):
        """Combine all partial decryptions to get the final result"""
        # Check if we have all required partial decryptions
        if len(self.partial_decryptions) < len(banks):
            return None, f"Not all banks have submitted partial decryptions ({len(self.partial_decryptions)}/{len(banks)})"
            
        try:
            # Combine all partial decryptions
            partial_list = list(self.partial_decryptions.values())
            result_ptxt = self.cc.MultipartyDecryptFusion(partial_list)
            result_ptxt.SetLength(1)
            
            # Get raw score and map to credit score range
            raw_score = result_ptxt.GetRealPackedValue()[0]
            credit_score = MIN_SCORE + (raw_score * (MAX_SCORE - MIN_SCORE))
            
            # Save the final result
            final_result = {
                "raw_score": float(raw_score),
                "credit_score": float(np.round(credit_score, 2))
            }
            
            with open(f"{RESULT_FOLDER}/final_credit_score.json", 'w') as f:
                json.dump(final_result, f, indent=4)
                
            return final_result, None
        except Exception as e:
            return None, str(e)