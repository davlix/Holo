import os
import hashlib
import logging
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from base64 import urlsafe_b64encode, urlsafe_b64decode
from getpass import getpass
from datetime import datetime
import tkinter as tk
from tkinter import filedialog, messagebox

logging.basicConfig(filename='encryption_activity.log', level=logging.INFO, format='%(asctime)s - %(message)s')

def generate_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return urlsafe_b64encode(kdf.derive(password.encode()))

def hash_file(file_path):
    hasher = hashlib.sha256()
    with open(file_path, 'rb') as file:
        buf = file.read()
        hasher.update(buf)
    return hasher.hexdigest()

def encrypt_file(file_path, key):
    try:
        original_hash = hash_file(file_path)
        
        with open(file_path, 'rb') as file:
            data = file.read()
        
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()

        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = iv + encryptor.update(padded_data) + encryptor.finalize()

        with open(file_path + ".enc", 'wb') as file:
            file.write(encrypted_data)
        
        with open(file_path + ".hash", 'w') as hash_file:
            hash_file.write(original_hash)
        
        os.remove(file_path)
        logging.info(f"File encrypted: {file_path}")
    except Exception as e:
        logging.error(f"Error encrypting file {file_path}: {e}")

def decrypt_file(file_path, key):
    try:
        with open(file_path, 'rb') as file:
            encrypted_data = file.read()
        
        iv = encrypted_data[:16]
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(encrypted_data[16:]) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()

        with open(file_path[:-4], 'wb') as file:
            file.write(data)
        
        with open(file_path[:-4] + ".hash", 'r') as hash_file:
            original_hash = hash_file.read().strip()
        
        os.remove(file_path)
        
        decrypted_hash = hash_file(file_path[:-4])
        if original_hash != decrypted_hash:
            logging.error(f"File integrity check failed for {file_path[:-4]}")
            raise ValueError(f"File integrity check failed for {file_path[:-4]}")
        
        os.remove(file_path[:-4] + ".hash")
        logging.info(f"File decrypted: {file_path[:-4]}")
    except Exception as e:
        logging.error(f"Error decrypting file {file_path}: {e}")

def encrypt_folder(folder_path, password):
    try:
        salt = os.urandom(16)
        key = generate_key(password, salt)
        
        for root, _, files in os.walk(folder_path):
            for file in files:
                file_path = os.path.join(root, file)
                encrypt_file(file_path, key)
        
        with open(os.path.join(folder_path, 'salt.key'), 'wb') as salt_file:
            salt_file.write(salt)
        logging.info(f"Folder encrypted: {folder_path}")
    except Exception as e:
        logging.error(f"Error encrypting folder {folder_path}: {e}")

def decrypt_folder(folder_path, password):
    try:
        with open(os.path.join(folder_path, 'salt.key'), 'rb') as salt_file:
            salt = salt_file.read()

        key = generate_key(password, salt)

        for root, _, files in os.walk(folder_path):
            for file in files:
                if file.endswith('.enc'):
                    file_path = os.path.join(root, file)
                    decrypt_file(file_path, key)
        
        os.remove(os.path.join(folder_path, 'salt.key'))
        logging.info(f"Folder decrypted: {folder_path}")
    except Exception as e:
        logging.error(f"Error decrypting folder {folder_path}: {e}")

def select_folder():
    folder_path = filedialog.askdirectory()
    folder_entry.delete(0, tk.END)
    folder_entry.insert(0, folder_path)

def start_encryption():
    folder_path = folder_entry.get()
    password = password_entry.get()
    if not folder_path or not password:
        messagebox.showwarning("Input Error", "Please enter both folder path and password")
        return

    encrypt_folder(folder_path, password)
    messagebox.showinfo("Success", "Folder encrypted successfully.")

def start_decryption():
    folder_path = folder_entry.get()
    password = password_entry.get()
    if not folder_path or not password:
        messagebox.showwarning("Input Error", "Please enter both folder path and password")
        return

    decrypt_folder(folder_path, password)
    messagebox.showinfo("Success", "Folder decrypted successfully.")

root = tk.Tk()
root.title("Folder Encryption/Decryption")

frame = tk.Frame(root)
frame.pack(pady=20)

folder_label = tk.Label(frame, text="Folder Path:")
folder_label.grid(row=0, column=0, padx=5, pady=5)

folder_entry = tk.Entry(frame, width=50)
folder_entry.grid(row=0, column=1, padx=5, pady=5)

folder_button = tk.Button(frame, text="Browse", command=select_folder)
folder_button.grid(row=0, column=2, padx=5, pady=5)

password_label = tk.Label(frame, text="Password:")
password_label.grid(row=1, column=0, padx=5, pady=5)

password_entry = tk.Entry(frame, show='*', width=50)
password_entry.grid(row=1, column=1, padx=5, pady=5)

encrypt_button = tk.Button(frame, text="Encrypt", command=start_encryption)
encrypt_button.grid(row=2, column=0, columnspan=3, pady=10)

decrypt_button = tk.Button(frame, text="Decrypt", command=start_decryption)
decrypt_button.grid(row=3, column=0, columnspan=3, pady=10)

root.mainloop()
