from flask import Flask, jsonify, send_from_directory
from .routes import register_routes
from .core.crypto_context import CryptoContextManager
import os

def create_app():
    """Create and configure the Flask application"""
    app = Flask(__name__)
    
    # Initialize crypto context
    CryptoContextManager()
    
    # Register API routes
    register_routes(app)
    
    # Add a basic index route
    @app.route('/')
    def index():
        return jsonify({
            "status": "success",
            "message": "MPC-FHE Server is running",
            "version": "1.0",
            "endpoints": [
                # Authentication
                {"path": "/api/register_bank", "method": "POST", "description": "Register a bank with the system"},
                {"path": "/api/list_banks", "method": "GET", "description": "List all registered banks"},
                
                # Key management
                {"path": "/api/generate_keys", "method": "POST", "description": "Generate keys for a bank"},
                {"path": "/api/eval_key_gen_round1", "method": "POST", "description": "First round of evaluation key generation"},
                {"path": "/api/eval_key_gen_round2", "method": "POST", "description": "Second round of evaluation key generation"},
                {"path": "/api/eval_key_final", "method": "POST", "description": "Finalize evaluation key generation"},
                {"path": "/api/upload_key", "method": "POST", "description": "Upload a key file"},
                
                # Data management
                {"path": "/api/upload_data", "method": "POST", "description": "Upload encrypted data"},
                {"path": "/api/list_data", "method": "GET", "description": "List all uploaded data"},
                {"path": "/api/list_files", "method": "GET", "description": "List all files in storage"},
                {"path": "/api/download_file/<filename>", "method": "GET", "description": "Download a file"},
                
                # Computation
                {"path": "/api/compute", "method": "POST", "description": "Perform homomorphic computation"},
                {"path": "/api/submit_partial_decrypt", "method": "POST", "description": "Submit partial decryption"},
                {"path": "/api/get_final_result", "method": "GET", "description": "Get final decryption result"},
                
                # System
                {"path": "/api/reset", "method": "POST", "description": "Reset server state"}
            ]
        })
    
    # Add a favicon handler
    @app.route('/favicon.ico')
    def favicon():
        return '', 204
    
    # Add error handlers
    @app.errorhandler(404)
    def not_found(e):
        return jsonify({
            "status": "error",
            "code": 404,
            "message": "The requested URL was not found on the server.",
            "tip": "Visit the root endpoint '/' for API documentation."
        }), 404
    
    @app.errorhandler(500)
    def server_error(e):
        return jsonify({
            "status": "error",
            "code": 500,
            "message": "An internal server error occurred.",
            "error": str(e)
        }), 500
    
    return app