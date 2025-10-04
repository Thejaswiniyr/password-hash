#!/usr/bin/env python3
"""
RAGFlow Hash API Service - Standalone Version
Can run without Docker using the requirements.txt dependencies
"""

import os
import sys
from flask import Flask, request, jsonify
import logging
from werkzeug.security import generate_password_hash, check_password_hash

# Try to import RAGFlow modules if available, otherwise use standalone mode
try:
    # Add RAGFlow path if available
    sys.path.insert(0, '/ragflow')
    from api.db.services.user_service import UserService
    from api.utils.crypt import decrypt, crypt
    RAGFLOW_AVAILABLE = True
    print("✅ RAGFlow modules available - using full RAGFlow functionality")
except ImportError:
    RAGFLOW_AVAILABLE = False
    print("⚠️  RAGFlow modules not available - using standalone mode")

app = Flask(__name__)

# Logging configuration
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "service": "ragflow-hash-api-standalone",
        "ragflow_available": RAGFLOW_AVAILABLE,
        "environment": "Standalone Python Environment"
    }), 200

@app.route('/hash', methods=['POST'])
def hash_password():
    """
    Hash a password using RAGFlow's exact method if available, otherwise standard method
    POST JSON body: {"password": "your_password_here"}
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON data provided"}), 400

        password = data.get('password')
        if not password or not isinstance(password, str):
            return jsonify({"error": "Password must be a string and required"}), 400

        if RAGFLOW_AVAILABLE:
            try:
                # Use RAGFlow's exact process: RSA encrypt -> decrypt -> hash
                encrypted_password = crypt(password)
                decrypted_password = decrypt(encrypted_password)
                hashed_password = generate_password_hash(decrypted_password)
                process = "RSA encrypt → RSA decrypt → generate_password_hash"
            except Exception as e:
                logger.warning(f"RAGFlow RSA process failed, using standard hash: {str(e)}")
                hashed_password = generate_password_hash(password)
                process = "generate_password_hash (fallback)"
        else:
            # Use standard Werkzeug hashing
            hashed_password = generate_password_hash(password)
            process = "generate_password_hash (standard)"

        logger.info(f"Password hashed successfully for request from {request.remote_addr}")
        return jsonify({
            "success": True,
            "hashed_password": hashed_password,
            "message": f"Password hashed successfully using {process}",
            "process": process,
            "ragflow_available": RAGFLOW_AVAILABLE
        }), 200

    except Exception as e:
        logger.error(f"Error hashing password: {str(e)}")
        return jsonify({"success": False, "error": "Internal server error", "message": str(e)}), 500

@app.route('/verify', methods=['POST'])
def verify_password():
    """
    Verify a password against a stored hash
    POST JSON body: {"password": "your_password", "hash": "stored_hash"}
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON data provided"}), 400

        password = data.get('password')
        stored_hash = data.get('hash')
        if not password or not stored_hash or not isinstance(password, str) or not isinstance(stored_hash, str):
            return jsonify({"error": "Password and hash must be strings and required"}), 400

        is_valid = check_password_hash(stored_hash, password)
        logger.info(f"Password verification {'successful' if is_valid else 'failed'} for request from {request.remote_addr}")
        return jsonify({"success": True, "is_valid": is_valid, "message": "Password verification completed"}), 200

    except Exception as e:
        logger.error(f"Error verifying password: {str(e)}")
        return jsonify({"success": False, "error": "Internal server error", "message": str(e)}), 500

@app.route('/test', methods=['GET'])
def test_hash_verification():
    """
    Test endpoint for password hashing and verification
    """
    try:
        password = "rakshitheju"
        
        if RAGFLOW_AVAILABLE:
            try:
                encrypted_password = crypt(password)
                decrypted_password = decrypt(encrypted_password)
                hash_result = generate_password_hash(decrypted_password)
                is_valid = check_password_hash(hash_result, decrypted_password)
                is_wrong = check_password_hash(hash_result, "wrongpassword")
                process = "RAGFlow RSA encrypt → decrypt → hash → verify"
            except Exception as e:
                logger.warning(f"RAGFlow process failed, using standard: {str(e)}")
                hash_result = generate_password_hash(password)
                is_valid = check_password_hash(hash_result, password)
                is_wrong = check_password_hash(hash_result, "wrongpassword")
                process = "Standard hash → verify (fallback)"
        else:
            hash_result = generate_password_hash(password)
            is_valid = check_password_hash(hash_result, password)
            is_wrong = check_password_hash(hash_result, "wrongpassword")
            process = "Standard hash → verify"

        return jsonify({
            "success": True,
            "test_password": password,
            "generated_hash": hash_result,
            "verification_correct": is_valid,
            "wrong_password_test": is_wrong,
            "process": process,
            "ragflow_available": RAGFLOW_AVAILABLE,
            "message": "Password hashing and verification test completed"
        }), 200

    except Exception as e:
        logger.error(f"Error in test: {str(e)}")
        return jsonify({"success": False, "error": "Test failed", "message": str(e)}), 500

if __name__ == '__main__':
    print("🚀 Starting RAGFlow Hash API Service (Standalone)...")
    print(f"📦 RAGFlow modules available: {RAGFLOW_AVAILABLE}")
    print("🔧 Available endpoints:")
    print("   GET  /health - Health check")
    print("   POST /hash - Hash password")
    print("   POST /verify - Verify password")
    print("   GET  /test - Test functionality")
    print("🌐 Service will be available at http://0.0.0.0:8082")
    
    app.run(host='0.0.0.0', port=8082, debug=True)
