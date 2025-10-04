#!/usr/bin/env python3
"""
Setup script for running RAGFlow Hash API in standalone mode
"""

import subprocess
import sys
import os

def install_requirements():
    """Install requirements from requirements.txt"""
    print("📦 Installing requirements...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        print("✅ Requirements installed successfully!")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install requirements: {e}")
        return False

def create_directories():
    """Create necessary directories"""
    dirs = ["api/utils", "conf"]
    for dir_path in dirs:
        os.makedirs(dir_path, exist_ok=True)
        print(f"📁 Created directory: {dir_path}")

def main():
    print("🚀 Setting up RAGFlow Hash API Service (Standalone)")
    print("=" * 50)
    
    # Create directories
    create_directories()
    
    # Install requirements
    if not install_requirements():
        print("❌ Setup failed!")
        return False
    
    print("\n✅ Setup completed successfully!")
    print("\n🔧 To run the service:")
    print("   python ragflow_hash_api_standalone.py")
    print("\n🌐 The service will be available at http://localhost:8082")
    
    return True

if __name__ == "__main__":
    main()
