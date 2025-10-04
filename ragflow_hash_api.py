#!/usr/bin/env python3
"""
RAGFlow Hash API Service
Uses RAGFlow's exact user_service.py functions in Docker environment
Provides endpoints to hash, verify passwords and test RAGFlow hashing methods.
"""

import sys
from flask import Flask, request, jsonify
import logging

# Add RAGFlow path so internal modules can be imported
sys.path.insert(0, '/ragflow')

try:
    # Import RAGFlow functions
    from api.db.services.user_service import UserService
    from werkzeug.security import generate_password_hash, check_password_hash
    from api.utils.crypt import decrypt, crypt
    print("✅ Successfully imported RAGFlow UserService and crypt functions")
except ImportError as e:
    print(f"❌ Failed to import RAGFlow modules: {e}")
    sys.exit(1)

app = Flask(__name__)

# Logging configuration
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "service": "ragflow-docker-hash-api",
        "method": "RAGFlow Docker UserService direct import",
        "environment": "RAGFlow Docker Container"
    }), 200


@app.route('/hash', methods=['POST'])
def hash_password():
    """
    Hash a password using RAGFlow's exact flow:
    RSA encrypt -> RSA decrypt -> generate_password_hash
    POST JSON body: {"password": "your_password_here"}
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON data provided"}), 400

        password = data.get('password')
        if not password or not isinstance(password, str):
            return jsonify({"error": "Password must be a string and required"}), 400

        try:
            encrypted_password = crypt(password)
            decrypted_password = decrypt(encrypted_password)
            hashed_password = generate_password_hash(decrypted_password)
        except Exception as e:
            logger.error(f"RSA encrypt/decrypt error: {str(e)}")
            return jsonify({"success": False, "error": "RSA encryption/decryption failed", "message": str(e)}), 500

        logger.info(f"Password hashed successfully for request from {request.remote_addr}")
        return jsonify({
            "success": True,
            "hashed_password": hashed_password,
            "message": "Password hashed successfully using RAGFlow RSA encrypt/decrypt + hash flow",
            "process": "RSA encrypt → RSA decrypt → generate_password_hash"
        }), 200

    except Exception as e:
        logger.error(f"Error hashing password: {str(e)}")
        return jsonify({"success": False, "error": "Internal server error", "message": str(e)}), 500


@app.route('/verify', methods=['POST'])
def verify_password():
    """
    Verify a password against a stored hash using RAGFlow UserService.
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
def test_ragflow_user_service():
    """
    Test endpoint for RAGFlow UserService compatibility.
    Uses sample password and runs RSA encrypt -> decrypt -> hash -> verify.
    """
    try:
        password = "rakshitheju"
        encrypted_password = crypt(password)
        decrypted_password = decrypt(encrypted_password)
        hash_result = generate_password_hash(decrypted_password)
        is_valid = check_password_hash(hash_result, decrypted_password)
        is_wrong = check_password_hash(hash_result, "wrongpassword")

        return jsonify({
            "success": True,
            "test_password": password,
            "generated_hash": hash_result,
            "verification_correct": is_valid,
            "wrong_password_test": is_wrong,
            "message": "RAGFlow Docker UserService compatibility test completed"
        }), 200

    except Exception as e:
        logger.error(f"Error in compatibility test: {str(e)}")
        return jsonify({"success": False, "error": "Test failed", "message": str(e)}), 500


@app.route('/test-ragflow-scrypt', methods=['GET'])
def test_ragflow_scrypt():
    """
    Test RAGFlow's actual Scrypt hash compatibility.
    GET /test-ragflow-scrypt
    """
    try:
        ragflow_scrypt_hash = "scrypt:32768:8:1$n6LdyfoQSiKZUDWs$5bee06eeb2832051303dfa877e6ca491ea85baf5465c35aa96f01ebb20db77ad5fc714494ea82297ee746186943cee2155afd8c5b7bceea2b28430b6e6c625cd"
        password = "rakshitheju"
        can_verify = check_password_hash(ragflow_scrypt_hash, password)

        return jsonify({
            "success": True,
            "ragflow_scrypt_hash": ragflow_scrypt_hash,
            "password": password,
            "can_verify": can_verify,
            "message": "RAGFlow Scrypt hash compatibility test completed"
        }), 200

    except Exception as e:
        logger.error(f"Error in Scrypt test: {str(e)}")
        return jsonify({"success": False, "error": "Scrypt test failed", "message": str(e)}), 500


if __name__ == '__main__':
    print("🚀 Starting RAGFlow Docker Hash API Service on port 8082...")
    app.run(host='0.0.0.0', port=8082, debug=True)
