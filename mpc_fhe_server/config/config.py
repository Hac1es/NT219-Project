import os

# Server configuration
PORT = 5000
DEBUG = True
HOST = '0.0.0.0'

# Storage paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'storage', 'uploads')
KEY_FOLDER = os.path.join(BASE_DIR, 'storage', 'keys')
CIPHERTEXT_FOLDER = os.path.join(BASE_DIR, 'storage', 'ciphertexts')
PARTIAL_DECRYPTION_FOLDER = os.path.join(BASE_DIR, 'storage', 'partial_decryptions')
RESULT_FOLDER = os.path.join(BASE_DIR, 'storage', 'results')

# Ensure storage folders exist
for folder in [UPLOAD_FOLDER, KEY_FOLDER, CIPHERTEXT_FOLDER, PARTIAL_DECRYPTION_FOLDER, RESULT_FOLDER]:
    os.makedirs(folder, exist_ok=True)

# Crypto parameters
MULTIPLICATIVE_DEPTH = 15
SCALING_MOD_SIZE = 59
BATCH_SIZE = 1

# Credit score parameters
MIN_SCORE = 300
MAX_SCORE = 850

# Weights for credit score calculation
WEIGHTS = {
    'w1': 0.35,  # S_payment
    'w2': 0.30,  # S_util
    'w3': 0.20,  # S_length
    'w4': 0.10,  # S_creditmix
    'w5': 0.05,  # S_inquiries
    'w6': 0.03,  # S_incomestability
    'w7': 0.02   # S_behavioral
}

# Required data types
REQUIRED_DATA_TYPES = ['S_payment', 'S_util', 'S_length', 'S_creditmix', 
                      'S_inquiries', 'S_behavioral', 'S_incomestability']