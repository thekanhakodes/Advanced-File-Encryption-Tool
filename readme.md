# 🔐 Advanced File Encryption Tool

A user-friendly, GUI-based file encryption and decryption tool that uses AES-256 encryption with password-derived keys to securely protect your files.

---

## 📝 Project Description

This Python-based application provides a secure way to encrypt and decrypt files using AES (Advanced Encryption Standard) with a 256-bit key. It features a simple graphical interface built with `tkinter`, making it easy for non-technical users to handle file encryption tasks. Ideal for personal use, small businesses, or anyone looking to protect sensitive data without needing command-line skills.

---

## ⚙️ Features

* 🔒 AES-256 encryption using password-derived keys (PBKDF2 + SHA-256)
* 🧂 Secure random salt and IV generation for every encryption
* 🗂️ File selection via GUI dialog (no command-line required)
* 🧑‍💻 Simple, beginner-friendly interface
* ✅ Error handling and user feedback through message boxes
* 🛡️ Encrypted files are saved with `.enc` extension; decrypted files use `.dec`

---

## 🧑‍💻 Technologies Used

* Python 3
* `tkinter` for GUI
* `cryptography` library for AES encryption (CBC mode with PKCS7-like padding)
* `secrets`, `base64`, and `os` for secure key and file handling

---

## 📦 Installation Instructions

1. **Clone the repository**

   ```bash
   git clone https://github.com/yourusername/encryption-tool.git
   cd encryption-tool
   ```

2. **Install dependencies**
   Make sure you have Python 3 installed. Then install the required packages:

   ```bash
   pip install cryptography
   ```

---

## ▶️ Usage

1. **Run the script**

   ```bash
   python encryption_tool.py
   ```

2. **Use the GUI**

   * Click "Encrypt File" to select and encrypt a file.
   * Click "Decrypt File" to decrypt a previously encrypted `.enc` file.
   * Enter the password when prompted (must match the one used during encryption).

---

## 💡 Future Improvements

* 🔐 Add support for password strength indicators
* 📁 Add batch encryption/decryption support
* 📦 Package as a standalone executable for Windows/Mac
* 🔍 Implement integrity checks (e.g., HMAC)

---

## 🖼️ UI Preview

> *(Optional: Insert a screenshot or GIF of the app here)*

---

## 📜 License

This project is licensed under the MIT License. See the `LICENSE` file for details.
