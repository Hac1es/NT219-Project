import os
import shutil
from ..config.config import KEY_FOLDER, CIPHERTEXT_FOLDER, PARTIAL_DECRYPTION_FOLDER, RESULT_FOLDER

class StorageManager:
    @staticmethod
    def save_key(bank_code, key_type, data):
        """Save a key file for a bank"""
        filename = f"{bank_code}_{key_type}_key.bin"
        filepath = os.path.join(KEY_FOLDER, filename)
        
        with open(filepath, 'wb') as f:
            f.write(data)
        
        return filepath
    
    @staticmethod
    def get_key_path(bank_code, key_type):
        """Get the path to a key file"""
        filename = f"{bank_code}_{key_type}_key.bin"
        return os.path.join(KEY_FOLDER, filename)
    
    @staticmethod
    def save_ciphertext(bank_code, data_type, data):
        """Save an encrypted data file"""
        filename = f"{bank_code}_{data_type}.bin"
        filepath = os.path.join(CIPHERTEXT_FOLDER, filename)
        
        with open(filepath, 'wb') as f:
            f.write(data)
        
        return filepath
    
    @staticmethod
    def save_partial_decryption(bank_code, data):
        """Save a partial decryption file"""
        filename = f"{bank_code}_partial.bin"
        filepath = os.path.join(PARTIAL_DECRYPTION_FOLDER, filename)
        
        with open(filepath, 'wb') as f:
            f.write(data)
        
        return filepath
    
    @staticmethod
    def save_result(filename, data):
        """Save a result file"""
        filepath = os.path.join(RESULT_FOLDER, filename)
        
        with open(filepath, 'wb') as f:
            f.write(data)
        
        return filepath
    
    @staticmethod
    def get_file(folder, filename):
        """Get a file from a specific folder"""
        if folder == 'keys':
            path = os.path.join(KEY_FOLDER, filename)
        elif folder == 'ciphertexts':
            path = os.path.join(CIPHERTEXT_FOLDER, filename)
        elif folder == 'partial_decryptions':
            path = os.path.join(PARTIAL_DECRYPTION_FOLDER, filename)
        elif folder == 'results':
            path = os.path.join(RESULT_FOLDER, filename)
        else:
            return None
            
        if not os.path.exists(path):
            return None
            
        with open(path, 'rb') as f:
            return f.read()
    
    @staticmethod
    def list_files(folder=None):
        """List files in a specific folder or all folders"""
        files = {}
        
        if folder == 'keys' or folder is None:
            files["keys"] = os.listdir(KEY_FOLDER)
        
        if folder == 'ciphertexts' or folder is None:
            files["ciphertexts"] = os.listdir(CIPHERTEXT_FOLDER)
        
        if folder == 'partial_decryptions' or folder is None:
            files["partial_decryptions"] = os.listdir(PARTIAL_DECRYPTION_FOLDER)
        
        if folder == 'results' or folder is None:
            files["results"] = os.listdir(RESULT_FOLDER)
        
        return files
    
    @staticmethod
    def clear_all_files():
        """Clear all files from all folders"""
        for folder in [KEY_FOLDER, CIPHERTEXT_FOLDER, PARTIAL_DECRYPTION_FOLDER, RESULT_FOLDER]:
            for filename in os.listdir(folder):
                file_path = os.path.join(folder, filename)
                if os.path.isfile(file_path):
                    os.unlink(file_path)