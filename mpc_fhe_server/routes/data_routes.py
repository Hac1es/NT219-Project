from flask import Blueprint, request, jsonify, send_from_directory
from werkzeug.utils import secure_filename
from ..services.computation_service import ComputationService
from ..core.storage import StorageManager
from ..config.config import REQUIRED_DATA_TYPES, KEY_FOLDER, CIPHERTEXT_FOLDER, PARTIAL_DECRYPTION_FOLDER, RESULT_FOLDER
from .auth_routes import banks
import os

data_bp = Blueprint('data', __name__)
computation_service = ComputationService()

@data_bp.route('/upload_data', methods=['POST'])
def upload_data():
    if 'file' not in request.files:
        # Handle JSON data
        data = request.json
        bank_code = data.get('bank_code')
        value = data.get('value')
        data_type = data.get('data_type')  # S_payment, S_util, etc.
        
        if not all([bank_code, value is not None, data_type]):
            return jsonify({"status": "error", "message": "Missing required parameters"}), 400
        
        if bank_code not in banks:
            return jsonify({"status": "error", "message": f"Bank {bank_code} not registered"}), 400
        
        if data_type not in REQUIRED_DATA_TYPES:
            return jsonify({
                "status": "error", 
                "message": f"Invalid data type. Must be one of: {', '.join(REQUIRED_DATA_TYPES)}"
            }), 400
        
        # Encrypt the data
        ciphertext, error = computation_service.encrypt_data(value, data_type, bank_code)
        
        if error:
            return jsonify({"status": "error", "message": error}), 500
        
        return jsonify({
            "status": "success",
            "message": f"Data {data_type} encrypted and saved",
            "data_type": data_type,
            "bank_code": bank_code
        })
    else:
        # Handle file upload
        file = request.files['file']
        bank_code = request.form.get('bank_code')
        data_type = request.form.get('data_type')
        
        if not all([file, bank_code, data_type]):
            return jsonify({"status": "error", "message": "Missing required parameters"}), 400
        
        if bank_code not in banks:
            return jsonify({"status": "error", "message": f"Bank {bank_code} not registered"}), 400
        
        if data_type not in REQUIRED_DATA_TYPES:
            return jsonify({
                "status": "error", 
                "message": f"Invalid data type. Must be one of: {', '.join(REQUIRED_DATA_TYPES)}"
            }), 400
        
        # Save the encrypted file
        filename = secure_filename(f"{bank_code}_{data_type}.bin")
        StorageManager.save_ciphertext(bank_code, data_type, file.read())
        
        return jsonify({
            "status": "success",
            "message": f"Data file for {data_type} uploaded",
            "data_type": data_type,
            "bank_code": bank_code
        })

@data_bp.route('/list_data', methods=['GET'])
def list_data():
    """List all uploaded data files"""
    data_files = {}
    
    # Group files by data type
    for data_type in REQUIRED_DATA_TYPES:
        data_files[data_type] = []
        for filename in os.listdir(CIPHERTEXT_FOLDER):
            if data_type in filename:
                bank_code = filename.replace(f"_{data_type}.bin", "")
                data_files[data_type].append(bank_code)
    
    # Check if we have all required data
    missing_data = []
    for data_type in REQUIRED_DATA_TYPES:
        if not data_files[data_type]:
            missing_data.append(data_type)
    
    return jsonify({
        "status": "success",
        "data_files": data_files,
        "missing_data": missing_data,
        "is_ready_for_computation": len(missing_data) == 0
    })

@data_bp.route('/download_file/<path:filename>', methods=['GET'])
def download_file(filename):
    """Download a file from any storage folder"""
    # Determine which folder contains the requested file
    for folder_name, folder_path in [
        ('keys', KEY_FOLDER),
        ('ciphertexts', CIPHERTEXT_FOLDER),
        ('partial_decryptions', PARTIAL_DECRYPTION_FOLDER),
        ('results', RESULT_FOLDER)
    ]:
        if os.path.exists(os.path.join(folder_path, filename)):
            return send_from_directory(folder_path, filename)
    
    return jsonify({
        "status": "error",
        "message": f"File {filename} not found"
    }), 404

@data_bp.route('/list_files', methods=['GET'])
def list_files():
    """List all files in storage"""
    folder = request.args.get('folder', None)
    return jsonify({
        "status": "success",
        "files": StorageManager.list_files(folder)
    })