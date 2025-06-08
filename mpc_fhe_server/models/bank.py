class Bank:
    def __init__(self, bank_code):
        self.bank_code = bank_code
        self.order = None  # Thứ tự tham gia
        self.status = "registered"
        self.keys = None
        self.key_paths = {
            "public": None,
            "private": None,
            "eval": None
        }
        self.partial_decrypt = None
        
    def set_order(self, order):
        """Set the participation order of this bank"""
        self.order = order
        
    def set_keys(self, keys):
        """Set the key pair for this bank"""
        self.keys = keys
        self.status = "keys_generated"
        
    def set_key_path(self, key_type, path):
        """Set the path to a key file"""
        self.key_paths[key_type] = path
        
    def set_partial_decrypt(self, partial):
        """Set the partial decryption"""
        self.partial_decrypt = partial
        
    def to_dict(self):
        """Convert the bank object to a dictionary"""
        return {
            "bank_code": self.bank_code,
            "order": self.order,
            "status": self.status,
            "has_public_key": self.key_paths["public"] is not None,
            "has_private_key": self.key_paths["private"] is not None,
            "has_eval_key": self.key_paths["eval"] is not None,
            "has_submitted_partial": self.partial_decrypt is not None
        }