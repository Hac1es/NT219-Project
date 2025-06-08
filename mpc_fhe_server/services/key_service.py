import openfhe as fhe
from ..core.crypto_context import CryptoContextManager
from ..core.serialization import serialize_to_file, deserialize_from_file
from ..core.storage import StorageManager

class KeyService:
    def __init__(self):
        self.cc_manager = CryptoContextManager()
        self.cc = self.cc_manager.get_context()
        
    def generate_initial_keys(self, bank):
        """Generate the initial key pair for the first bank"""
        keys = self.cc.KeyGen()
        bank.set_keys(keys)
        
        # Save keys to files
        pub_path = StorageManager.get_key_path(bank.bank_code, "public")
        prv_path = StorageManager.get_key_path(bank.bank_code, "private")
        
        serialize_to_file(keys.publicKey, pub_path)
        serialize_to_file(keys.secretKey, prv_path)
        
        bank.set_key_path("public", pub_path)
        bank.set_key_path("private", prv_path)
        
        return keys
        
    def generate_multiparty_keys(self, bank, prev_bank):
        """Generate a key pair for subsequent banks"""
        # Load previous bank's public key
        prev_pub_path = prev_bank.key_paths["public"]
        prev_public_key, success = deserialize_from_file(prev_pub_path, "public_key")
        
        if not success:
            return None, "Failed to load previous bank's public key"
        
        # Generate multiparty keys
        keys = self.cc.MultipartyKeyGen(prev_public_key)
        bank.set_keys(keys)
        
        # Save keys to files
        pub_path = StorageManager.get_key_path(bank.bank_code, "public")
        prv_path = StorageManager.get_key_path(bank.bank_code, "private")
        
        serialize_to_file(keys.publicKey, pub_path)
        serialize_to_file(keys.secretKey, prv_path)
        
        bank.set_key_path("public", pub_path)
        bank.set_key_path("private", prv_path)
        
        return keys, None
    
    def generate_eval_key_round1(self, bank):
        """Generate the initial evaluation key for the first bank"""
        if not bank.keys:
            return None, "Bank keys not found"
            
        eval_key = self.cc.KeySwitchGen(bank.keys.secretKey, bank.keys.secretKey)
        
        # Save evaluation key
        eval_path = StorageManager.get_key_path(bank.bank_code, "eval")
        serialize_to_file(eval_key, eval_path)
        bank.set_key_path("eval", eval_path)
        
        return eval_key, None
    
    def generate_eval_key_round2(self, bank, prev_bank):
        """Generate and combine evaluation keys for subsequent banks"""
        if not bank.keys:
            return None, "Bank keys not found"
            
        # Load previous evaluation key
        prev_eval_path = prev_bank.key_paths["eval"]
        prev_eval_key, success = deserialize_from_file(prev_eval_path, "eval_key")
        
        if not success:
            return None, "Failed to load previous evaluation key"
        
        # Generate and combine the new key part
        new_key_part = self.cc.MultiKeySwitchGen(bank.keys.secretKey, bank.keys.secretKey, prev_eval_key)
        accumulated_key = self.cc.MultiAddEvalKeys(prev_eval_key, new_key_part, bank.keys.publicKey.GetKeyTag())
        
        # Save the accumulated key
        eval_path = StorageManager.get_key_path(bank.bank_code, "eval")
        serialize_to_file(accumulated_key, eval_path)
        bank.set_key_path("eval", eval_path)
        
        return accumulated_key, None
    
    def finalize_eval_key(self, banks, last_bank):
        """Generate the final evaluation key from all banks' contributions"""
        if not self.cc_manager.get_joint_public_key():
            return None, "Joint public key not set"
            
        # Get the final accumulated key
        eval_mult_ab = deserialize_from_file(last_bank.key_paths["eval"], "eval_key")[0]
        
        # Each bank needs to generate their final key part
        final_key_parts = []
        for bank in banks.values():
            if not bank.keys:
                return None, f"Keys not found for bank {bank.bank_code}"
                
            part = self.cc.MultiMultEvalKey(bank.keys.secretKey, eval_mult_ab, 
                                          self.cc_manager.get_joint_public_key().GetKeyTag())
            final_key_parts.append(part)
        
        # Combine all parts
        if not final_key_parts:
            return None, "No key parts generated"
            
        eval_mult_final = final_key_parts[0]
        for i in range(1, len(final_key_parts)):
            eval_mult_final = self.cc.MultiAddEvalMultKeys(
                eval_mult_final, final_key_parts[i], eval_mult_final.GetKeyTag())
        
        # Insert the final evaluation key
        self.cc.InsertEvalMultKey([eval_mult_final])
        
        # Save and set the key
        final_key_path = StorageManager.get_key_path("joint", "eval_mult")
        serialize_to_file(eval_mult_final, final_key_path)
        self.cc_manager.set_eval_mult_key(eval_mult_final)
        
        return eval_mult_final, None