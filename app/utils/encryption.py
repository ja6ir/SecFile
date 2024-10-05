import os
from cryptography.fernet import Fernet
from flask import current_app
import hashlib

def generate_key():
    return Fernet.generate_key()

def calculate_checksum(file_content):
    """Calculate a secure SHA-256 checksum of the file content."""
    sha256 = hashlib.sha256()
    sha256.update(file_content)
    return sha256.hexdigest()

def encrypt_file(file):
    # Generate a new encryption key
    key = generate_key()
    fernet = Fernet(key)
    
    # Read the file contents
    file_content = file.read()
    
    # Encrypt the file content
    encrypted_content = fernet.encrypt(file_content)
    
    # Save the encrypted file to a specific path
    encrypted_file_path = os.path.join('app/encrypted_files', file.filename)
    with open(encrypted_file_path, 'wb') as encrypted_file:
        encrypted_file.write(encrypted_content)
    
    # Calculate checksum using SHA-256 (more appropriate for file integrity verification)
    checksum = calculate_checksum(file_content)
    
    # Return the encrypted file path, the encryption key, and the checksum
    return encrypted_file_path, key.decode('utf-8'), checksum

def decrypt_file(encrypted_path, key, original_filename):
    # Use current_app.root_path to get the absolute path to the app directory
    decrypted_dir = os.path.join(current_app.root_path, 'decrypted_files')

    # Ensure the directory exists
    if not os.path.exists(decrypted_dir):
        os.makedirs(decrypted_dir)

    # Build the full decrypted file path
    decrypted_file_path = os.path.join(decrypted_dir, original_filename)

    # Perform decryption
    fernet = Fernet(key.encode('utf-8'))
    with open(encrypted_path, 'rb') as encrypted_file:
        encrypted_data = encrypted_file.read()
    with open(decrypted_file_path, 'wb') as decrypted_file:
        decrypted_file.write(fernet.decrypt(encrypted_data))

    return decrypted_file_path
