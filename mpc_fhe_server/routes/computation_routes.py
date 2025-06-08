from flask import Blueprint, request, jsonify
from ..services.computation_service import ComputationService
from ..services.decryption_service import DecryptionService
from .auth_routes import banks

comp_bp = Blueprint('computation', __name__)
computation_service = ComputationService()
decryption_service = DecryptionService()

@comp_bp.route('/compute', methods=['POST'])
def compute():
    """Perform homomorphic computation on encrypted data"""
    # Check if we have all required data
    success, error = computation_service.load_encrypted_data()
    
    if not success:
        return jsonify({
            "status": "error",
            "message": error
        }), 400
    
    # Perform the computation
    result, error = computation_service.compute_credit_score()
    
    if error:
        return jsonify({
            "status": "error",
            "message": f"Computation failed: {error}"
        }), 500
    
    return jsonify({
        "status": "success",
        "message": "Credit score computation completed"
    })

@comp_bp.route('/submit_partial_decrypt', methods=['POST'])
def submit_partial_decrypt():
    """Submit a partial decryption from a bank"""
    if 'file' not in request.files:
        # Handle direct partial decryption
        data = request.json
        bank_code = data.get('bank_code')
        is_lead = data.get('is_lead', False)
        
        if not bank_code:
            return jsonify({"status": "error", "message": "Bank code is required"}), 400
        
        if bank_code not in banks:
            return jsonify({"status": "error", "message": f"Bank {bank_code} not registered"}), 400
        
        bank = banks[bank_code]
        
        partial, error = decryption_service.create_partial_decryption(bank, is_lead)
        
        if error:
            return jsonify({"status": "error", "message": error}), 500
        
        return jsonify({
            "status": "success",
            "message": f"Partial decryption from bank {bank_code} created and saved",
            "bank": bank.to_dict()
        })
    else:
        # Handle file upload
        file = request.files['file']
        bank_code = request.form.get('bank_code')
        
        if not bank_code:
            return jsonify({"status": "error", "message": "Bank code is required"}), 400
        
        if bank_code not in banks:
            return jsonify({"status": "error", "message": f"Bank {bank_code} not registered"}), 400
        
        partial, error = decryption_service.submit_partial_decryption_file(bank_code, file.read())
        
        if error:
            return jsonify({"status": "error", "message": error}), 500
        
        return jsonify({
            "status": "success",
            "message": f"Partial decryption file uploaded for bank {bank_code}"
        })

@comp_bp.route('/get_final_result', methods=['GET'])
def get_final_result():
    """Combine all partial decryptions and get the final result"""
    final_result, error = decryption_service.finalize_decryption(banks)
    
    if error:
        return jsonify({"status": "error", "message": error}), 500
    
    return jsonify({
        "status": "success",
        "message": "Final decryption completed",
        "raw_score": final_result["raw_score"],
        "credit_score": final_result["credit_score"]
    })