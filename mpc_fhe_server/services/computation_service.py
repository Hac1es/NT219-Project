import numpy as np
import openfhe as fhe
import os
from ..core.crypto_context import CryptoContextManager
from ..core.serialization import serialize_to_file, deserialize_from_file
from ..core.storage import StorageManager
from ..config.config import WEIGHTS, REQUIRED_DATA_TYPES, CIPHERTEXT_FOLDER, RESULT_FOLDER

class ComputationService:
    def __init__(self):
        self.cc_manager = CryptoContextManager()
        self.cc = self.cc_manager.get_context()
        self.encrypted_data = {}
        self.encrypted_result = None
    
    def encrypt_data(self, value, data_type, bank_code):
        """Encrypt a single data point"""
        if not self.cc_manager.get_joint_public_key():
            return None, "Joint public key not available"
            
        try:
            # Create plaintext
            plaintext = self.cc.MakeCKKSPackedPlaintext([float(value)])
            
            # Encrypt with joint public key
            ciphertext = self.cc.Encrypt(self.cc_manager.get_joint_public_key(), plaintext)
            
            # Save ciphertext
            filepath = f"{CIPHERTEXT_FOLDER}/{bank_code}_{data_type}.bin"
            serialize_to_file(ciphertext, filepath)
            
            # Cache encrypted data
            self.encrypted_data[data_type] = ciphertext
            
            return ciphertext, None
        except Exception as e:
            return None, str(e)
    
    def load_encrypted_data(self):
        """Load all encrypted data files into memory"""
        self.encrypted_data = {}
        
        for data_type in REQUIRED_DATA_TYPES:
            found = False
            
            # Look for files containing this data type
            for filename in os.listdir(CIPHERTEXT_FOLDER):
                if data_type in filename:
                    filepath = f"{CIPHERTEXT_FOLDER}/{filename}"
                    ciphertext, success = deserialize_from_file(filepath, "ciphertext")
                    
                    if success:
                        self.encrypted_data[data_type] = ciphertext
                        found = True
                        break
            
            if not found:
                return False, f"Data for {data_type} not found"
                
        return True, None
    
    def compute_credit_score(self):
        """Compute the encrypted credit score using homomorphic operations"""
        # Make sure we have all required data
        for data_type in REQUIRED_DATA_TYPES:
            if data_type not in self.encrypted_data:
                return None, f"Missing data: {data_type}"
        
        try:
            # Extract encrypted data
            S_payment = self.encrypted_data['S_payment']
            S_util = self.encrypted_data['S_util']
            S_length = self.encrypted_data['S_length']
            S_creditmix = self.encrypted_data['S_creditmix']
            S_inquiries = self.encrypted_data['S_inquiries']
            S_behavioral = self.encrypted_data['S_behavioral']
            S_incomestability = self.encrypted_data['S_incomestability']
            
            # Tính toán thông số A
            S_inquiries_sq = self.cc.EvalMult(S_inquiries, S_inquiries)
            A = self.cc.EvalAdd(S_util, S_inquiries_sq)
            
            # Tính toán thông số B
            total = self.cc.EvalAdd(S_creditmix, S_incomestability)
            total = self.cc.EvalAdd(total, self.cc.MakeCKKSPackedPlaintext([1.0]))
            B = self.cc.EvalChebyshevFunction(
                func=lambda x: np.sqrt(x),
                ciphertext=total,
                a=1.0,
                b=3.0,
                degree=15
            )
            
            # Tính toán thông số thứ nhất
            w1 = WEIGHTS['w1']
            w1_p = self.cc.MakeCKKSPackedPlaintext([w1])
            S_payment_scaled = self.cc.EvalMult(S_payment, w1_p)
            param1 = self.cc.EvalMult(S_payment_scaled, S_payment_scaled)
            
            # Tính toán thông số thứ hai
            w2 = WEIGHTS['w2']
            w7 = WEIGHTS['w7']
            w2_p = self.cc.MakeCKKSPackedPlaintext([w2])
            w7_p = self.cc.MakeCKKSPackedPlaintext([w7])
            S_util_scaled = self.cc.EvalMult(S_util, w2_p)
            S_behavioral_scaled = self.cc.EvalMult(S_behavioral, w7_p)
            S_behavioral_scaled = self.cc.EvalMult(S_behavioral_scaled, S_behavioral_scaled)
            S_behavioral_scaled = self.cc.EvalMult(S_behavioral_scaled, self.cc.MakeCKKSPackedPlaintext([3.0]))
            param2_inner = self.cc.EvalAdd(S_util_scaled, S_behavioral_scaled)
            param2 = self.cc.EvalChebyshevFunction(
                func=lambda x: np.sqrt(x),
                ciphertext=param2_inner,
                a=0.0,
                b=0.3012,
                degree=15
            )
            
            # Tính toán thông số thứ ba
            w3 = WEIGHTS['w3']
            w4 = WEIGHTS['w4']
            w3_p = self.cc.MakeCKKSPackedPlaintext([w3])
            w4_p = self.cc.MakeCKKSPackedPlaintext([w4])
            S_length_scaled = self.cc.EvalMult(S_length, w3_p)
            S_creditmix_scaled = self.cc.EvalMult(S_creditmix, w4_p)
            S_creditmix_scaledsqed = self.cc.EvalMult(S_creditmix_scaled, S_creditmix_scaled)
            B_plus = self.cc.EvalAdd(B, self.cc.MakeCKKSPackedPlaintext([1.0]))
            B_plus_inverse = self.cc.EvalDivide(self.cc.MakeCKKSPackedPlaintext([1.0]), B_plus, 1.0, 2.0, 7)
            S_total = self.cc.EvalAdd(S_length_scaled, S_creditmix_scaledsqed)
            param3 = self.cc.EvalMult(S_total, B_plus_inverse)
            
            # Tính toán thông số thứ tư
            w5 = WEIGHTS['w5']
            w6 = WEIGHTS['w6']
            w5_p = self.cc.MakeCKKSPackedPlaintext([w5])
            w6_p = self.cc.MakeCKKSPackedPlaintext([w6])
            S_inquiries_scaled = self.cc.EvalMult(S_inquiries, w5_p)
            S_incomestability_scaled = self.cc.EvalMult(S_incomestability, w6_p)
            param4 = self.cc.EvalAdd(S_inquiries_scaled, S_incomestability_scaled)
            
            # Tính điểm tín dụng cuối cùng
            credit_score_encrypted = self.cc.EvalAdd(param1, param2)
            credit_score_encrypted = self.cc.EvalAdd(credit_score_encrypted, param3)
            credit_score_encrypted = self.cc.EvalAdd(credit_score_encrypted, param4)
            
            # Save result
            self.encrypted_result = credit_score_encrypted
            result_path = f"{RESULT_FOLDER}/encrypted_credit_score.bin"
            serialize_to_file(credit_score_encrypted, result_path)
            
            return credit_score_encrypted, None
        except Exception as e:
            return None, str(e)
    
    def get_encrypted_result(self):
        """Get the encrypted result, loading from file if necessary"""
        if self.encrypted_result is None:
            result_path = f"{RESULT_FOLDER}/encrypted_credit_score.bin"
            if os.path.exists(result_path):
                self.encrypted_result, success = deserialize_from_file(result_path, "ciphertext")
                if not success:
                    return None, "Failed to load encrypted result"
            else:
                return None, "No encrypted result available"
                
        return self.encrypted_result, None