"""
Advanced File Encryption Tool
Author: thekanhakodes
GitHub: https://github.com/thekanhakodes/encryption-tool
"""

import os
import tkinter as tk
from tkinter import filedialog, simpledialog, messagebox
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import secrets

# ========== Constants ==========
KEY_LENGTH = 32  # For AES-256
SALT_SIZE = 16
IV_SIZE = 16
ITERATIONS = 100_000

# ========== Crypto Functions ==========

def derive_key(password: str, salt: bytes) -> bytes:
    """Derives a secure AES key from the password and salt using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_file(filepath: str, password: str):
    with open(filepath, 'rb') as f:
        data = f.read()

    salt = secrets.token_bytes(SALT_SIZE)
    iv = secrets.token_bytes(IV_SIZE)
    key = derive_key(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Padding (PKCS7 manual)
    pad_len = 16 - (len(data) % 16)
    data += bytes([pad_len]) * pad_len

    encrypted_data = encryptor.update(data) + encryptor.finalize()

    out_file = filepath + '.enc'
    with open(out_file, 'wb') as f:
        f.write(salt + iv + encrypted_data)

    print(f"[✓] Encrypted: {out_file} (created by thekanhakodes)")
    messagebox.showinfo("Success", f"File encrypted and saved as:\n{out_file}")

def decrypt_file(filepath: str, password: str):
    with open(filepath, 'rb') as f:
        file_data = f.read()

    salt = file_data[:SALT_SIZE]
    iv = file_data[SALT_SIZE:SALT_SIZE+IV_SIZE]
    encrypted_data = file_data[SALT_SIZE+IV_SIZE:]

    key = derive_key(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_padded = decryptor.update(encrypted_data) + decryptor.finalize()

    # Remove padding
    pad_len = decrypted_padded[-1]
    decrypted_data = decrypted_padded[:-pad_len]

    out_file = filepath.replace('.enc', '') + '.dec'
    with open(out_file, 'wb') as f:
        f.write(decrypted_data)

    print(f"[✓] Decrypted: {out_file} (powered by github.com/thekanhakodes)")
    messagebox.showinfo("Success", f"File decrypted and saved as:\n{out_file}")

# ========== GUI Interface ==========

def select_file_encrypt():
    filepath = filedialog.askopenfilename(title="Select file to encrypt")
    if filepath:
        password = simpledialog.askstring("Password", "Enter encryption password:", show='*')
        if password:
            try:
                encrypt_file(filepath, password)
            except Exception as e:
                print(f"[!] Encryption error: {e}")
                messagebox.showerror("Error", f"Encryption failed:\n{str(e)}")

def select_file_decrypt():
    filepath = filedialog.askopenfilename(title="Select .enc file to decrypt")
    if filepath:
        password = simpledialog.askstring("Password", "Enter decryption password:", show='*')
        if password:
            try:
                decrypt_file(filepath, password)
            except Exception as e:
                print(f"[!] Decryption error: {e}")
                messagebox.showerror("Error", f"Decryption failed:\n{str(e)}")

def main():
    print("🚀 Advanced File Encryption Tool launched (by thekanhakodes)\n")
    root = tk.Tk()
    root.title("Advanced Encryption Tool")
    root.geometry("400x200")
    root.resizable(False, False)

    label = tk.Label(root, text="Advanced File Encryption Tool", font=("Helvetica", 16))
    label.pack(pady=20)

    encrypt_btn = tk.Button(root, text="Encrypt File", command=select_file_encrypt, width=20, height=2)
    encrypt_btn.pack(pady=5)

    decrypt_btn = tk.Button(root, text="Decrypt File", command=select_file_decrypt, width=20, height=2)
    decrypt_btn.pack(pady=5)

    root.mainloop()

if __name__ == "__main__":
    main()
