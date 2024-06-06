from flask import Flask, request, jsonify
import subprocess
import base64
import os
import crypt
from OpenSSL import crypto
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

app = Flask(__name__)

# Load the private key
with open("/etc/ssl/certs/ef-private.pem", "rb") as key_file:
    private_key = RSA.import_key(key_file.read())

def decrypt(encrypted_data):
    decoded_data = base64.b64decode(encrypted_data)
    cipher_rsa = PKCS1_OAEP.new(private_key)
    decrypted_data = cipher_rsa.decrypt(decoded_data)
    return decrypted_data.decode('utf-8')

def hash_password(password):
    salt = crypt.mksalt(crypt.METHOD_SHA512)
    hashed_password = crypt.crypt(password, salt)
    return hashed_password

@app.route('/user', methods=['POST'])
def manage_user():
    data = request.json
    encrypted_id = data.get('id')
    encrypted_token = data.get('token')

    if not encrypted_id or not encrypted_token:
        return jsonify({"error": "Invalid input"}), 400

    try:
        user_id = decrypt(encrypted_id)
        token = decrypt(encrypted_token)
    except Exception as e:
        return jsonify({"error": "Decryption failed", "details": str(e)}), 500

    print(user_id)
    print(token)
    try:
        hashed_token = hash_password(token)
        # Check if the user already exists
        result = subprocess.run(['id', '-u', user_id], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode == 0:
            # User exists, update password
            subprocess.run(['sudo', 'usermod', '--password', hashed_token, user_id], check=True)
            return jsonify({"status": "User password updated"}), 200
        else:
            # User does not exist, create user
            subprocess.run(['sudo', 'useradd', '-m', '-p', hashed_token, user_id], check=True)
            return jsonify({"status": "User created"}), 201
    except Exception as e:
        return jsonify({"error": "User management failed", "details": str(e)}), 500

if __name__ == '__main__':
    app.run(ssl_context=('/etc/ssl/certs/ef-public.pem', '/etc/ssl/certs/ef-private.pem'), debug=True)
