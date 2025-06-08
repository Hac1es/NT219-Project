from flask import Blueprint, request, jsonify
from ..models.bank import Bank

# Global dictionary to store bank instances
banks = {}

# Blueprint for authentication routes
auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register_bank', methods=['POST'])
def register_bank():
    data = request.json
    bank_code = data.get('bank_code')
    
    if not bank_code:
        return jsonify({"status": "error", "message": "Bank code is required"}), 400
    
    if bank_code in banks:
        return jsonify({"status": "error", "message": f"Bank {bank_code} already registered"}), 400
    
    # Create a new bank instance and assign order
    bank = Bank(bank_code)
    bank.set_order(len(banks) + 1)
    
    # Add to global banks dictionary
    banks[bank_code] = bank
    
    return jsonify({
        "status": "success", 
        "message": f"Bank {bank_code} registered successfully",
        "bank": bank.to_dict()
    })

@auth_bp.route('/list_banks', methods=['GET'])
def list_banks():
    """List all registered banks"""
    return jsonify({
        "status": "success",
        "banks": {code: bank.to_dict() for code, bank in banks.items()},
        "count": len(banks)
    })

@auth_bp.route('/reset', methods=['POST'])
def reset():
    """Reset the system state"""
    global banks
    
    # Clear the bank data
    banks = {}
    
    # Reset the crypto context
    from ..core.crypto_context import CryptoContextManager
    CryptoContextManager().reset()
    
    # Clear stored files
    from ..core.storage import StorageManager
    StorageManager.clear_all_files()
    
    return jsonify({
        "status": "success",
        "message": "System state has been reset"
    })