import openfhe as fhe
from ..config.config import MULTIPLICATIVE_DEPTH, SCALING_MOD_SIZE, BATCH_SIZE

class CryptoContextManager:
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(CryptoContextManager, cls).__new__(cls)
            cls._instance.initialize()
        return cls._instance
    
    def initialize(self):
        """Initialize the crypto context with CKKS parameters"""
        parameters = fhe.CCParamsCKKSRNS()
        parameters.SetMultiplicativeDepth(MULTIPLICATIVE_DEPTH)
        parameters.SetScalingModSize(SCALING_MOD_SIZE)
        parameters.SetBatchSize(BATCH_SIZE)

        self.cc = fhe.GenCryptoContext(parameters)
        self.cc.Enable(fhe.PKESchemeFeature.PKE)
        self.cc.Enable(fhe.PKESchemeFeature.KEYSWITCH)
        self.cc.Enable(fhe.PKESchemeFeature.LEVELEDSHE)
        self.cc.Enable(fhe.PKESchemeFeature.ADVANCEDSHE)
        self.cc.Enable(fhe.PKESchemeFeature.MULTIPARTY)
        
        self.joint_public_key = None
        self.eval_mult_key = None
    
    def get_context(self):
        """Get the OpenFHE crypto context"""
        return self.cc
    
    def set_joint_public_key(self, key):
        """Set the joint public key used by all parties"""
        self.joint_public_key = key
    
    def get_joint_public_key(self):
        """Get the joint public key"""
        return self.joint_public_key
    
    def set_eval_mult_key(self, key):
        """Set the evaluation multiplication key"""
        self.eval_mult_key = key
        self.cc.InsertEvalMultKey([key])
    
    def get_eval_mult_key(self):
        """Get the evaluation multiplication key"""
        return self.eval_mult_key
    
    def reset(self):
        """Reset the crypto context"""
        self.joint_public_key = None
        self.eval_mult_key = None
        self.initialize()