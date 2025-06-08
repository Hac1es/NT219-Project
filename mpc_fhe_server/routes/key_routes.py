from flask import Blueprint, request, jsonify, send_from_directory
from werkzeug.utils import secure_filename
from ..services.key_service import KeyService
from ..core.storage import StorageManager
from ..core.crypto_context import CryptoContextManager
from .auth_routes import banks
import os

key_bp = Blueprint('keys', __name__)
key_service = KeyService()

@key_bp.route('/generate_keys', methods=['POST'])
def generate_keys():
    data = request.json
    bank_code = data.get('bank_code')
    
    if not bank_code:
        return jsonify({"status": "error", "message": "Bank code is required"}), 400
    
    if bank_code not in banks:
        return jsonify({"status": "error", "message": f"Bank {bank_code} not registered"}), 400
    
    bank = banks[bank_code]
    
    # Generate keys based on bank order
    if bank.order == 1:
        # First bank generates initial keys
        keys = key_service.generate_initial_keys(bank)
        
        return jsonify({
            "status": "success",
            "message": "Initial key pair generated",
            "bank": bank.to_dict()
        })
    else:
        # Find the previous bank
        prev_bank = None
        for code, b in banks.items():
            if b.order == bank.order - 1:
                prev_bank = b
                break
        
        if not prev_bank:
            return jsonify({
                "status": "error", 
                "message": "Previous bank not found"
            }), 400
            
        keys, error = key_service.generate_multiparty_keys(bank, prev_bank)
        
        if error:
            return jsonify({"status": "error", "message": error}), 500
            
        # If this is the last bank, set the joint public key
        if bank.order == len(banks):
            CryptoContextManager().set_joint_public_key(keys.publicKey)
            # Save joint public key
            joint_key_path = StorageManager.get_key_path("joint", "public")
            from ..core.serialization import serialize_to_file
            serialize_to_file(keys.publicKey, joint_key_path)
            
            return jsonify({
                "status": "success",
                "message": "Multiparty keys generated and joint public key created",
                "bank": bank.to_dict(),
                "is_final": True
            })
        else:
            return jsonify({
                "status": "success",
                "message": f"Multiparty keys generated for bank {bank_code}",
                "bank": bank.to_dict()
            })

@key_bp.route('/eval_key_gen_round1', methods=['POST'])
def eval_key_gen_round1():
    data = request.json
    bank_code = data.get('bank_code')
    
    if not bank_code:
        return jsonify({"status": "error", "message": "Bank code is required"}), 400
    
    if bank_code not in banks:
        return jsonify({"status": "error", "message": f"Bank {bank_code} not registered"}), 400
    
    bank = banks[bank_code]
    
    if bank.order != 1:
        return jsonify({
            "status": "error", 
            "message": "Only the first bank can initiate evaluation key generation"
        }), 400
    
    eval_key, error = key_service.generate_eval_key_round1(bank)
    
    if error:
        return jsonify({"status": "error", "message": error}), 500
    
    return jsonify({
        "status": "success",
        "message": "Initial evaluation key generated",
        "bank": bank.to_dict()
    })

@key_bp.route('/eval_key_gen_round2', methods=['POST'])
def eval_key_gen_round2():
    data = request.json
    bank_code = data.get('bank_code')
    
    if not bank_code:
        return jsonify({"status": "error", "message": "Bank code is required"}), 400
    
    if bank_code not in banks:
        return jsonify({"status": "error", "message": f"Bank {bank_code} not registered"}), 400
    
    bank = banks[bank_code]
    
    if bank.order == 1:
        return jsonify({
            "status": "error", 
            "message": "First bank already generated initial evaluation key"
        }), 400
    
    # Find the previous bank
    prev_bank = None
    for code, b in banks.items():
        if b.order == bank.order - 1:
            prev_bank = b
            break
    
    if not prev_bank:
        return jsonify({
            "status": "error", 
            "message": "Previous bank not found"
        }), 400
    
    accumulated_key, error = key_service.generate_eval_key_round2(bank, prev_bank)
    
    if error:
        return jsonify({"status": "error", "message": error}), 500
    
    return jsonify({
        "status": "success",
        "message": f"Evaluation key updated for bank {bank_code}",
        "bank": bank.to_dict()
    })

@key_bp.route('/eval_key_final', methods=['POST'])
def eval_key_final():
    # Get the last bank by order
    last_bank = None
    max_order = 0
    
    for code, bank in banks.items():
        if bank.order > max_order:
            max_order = bank.order
            last_bank = bank
    
    if not last_bank:
        return jsonify({
            "status": "error", 
            "message": "No banks registered"
        }), 400
    
    eval_mult_final, error = key_service.finalize_eval_key(banks, last_bank)
    
    if error:
        return jsonify({"status": "error", "message": error}), 500
    
    return jsonify({
        "status": "success",
        "message": "Joint evaluation key generated and inserted"
    })

@key_bp.route('/upload_key', methods=['POST'])
def upload_key():
    if 'file' not in request.files:
        return jsonify({"status": "error", "message": "No file part"}), 400
    
    file = request.files['file']
    bank_code = request.form.get('bank_code')
    key_type = request.form.get('key_type')  # 'public', 'private', or 'eval'
    
    if not all([file, bank_code, key_type]):
        return jsonify({"status": "error", "message": "Missing required parameters"}), 400
    
    if bank_code not in banks:
        return jsonify({"status": "error", "message": f"Bank {bank_code} not registered"}), 400
    
    bank = banks[bank_code]
    
    filename = secure_filename(f"{bank_code}_{key_type}_key.bin")
    filepath = StorageManager.save_key(bank_code, key_type, file.read())
    
    # Update bank key paths
    bank.set_key_path(key_type, filepath)
    
    return jsonify({
        "status": "success", 
        "message": f"{key_type.capitalize()} key uploaded for bank {bank_code}",
        "bank": bank.to_dict()
    })