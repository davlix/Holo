import os
import hashlib
import logging
import platform
import win32security
import pywintypes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from base64 import urlsafe_b64encode, urlsafe_b64decode
from getpass import getpass
from datetime import datetime
import tkinter as tk
from tkinter import filedialog, messagebox
import time
import threading

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

def hide_file(file_path):
    os.system(f'attrib +h "{file_path}"')

def unhide_file(file_path):
    os.system(f'attrib -h "{file_path}"')

def encrypt_file_double(file_path, key):
    try:
        original_hash = hash_file(file_path)
        
        with open(file_path, 'rb') as file:
            data = file.read()
        
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()

        iv_aes = os.urandom(16)
        cipher_aes = Cipher(algorithms.AES(key), modes.CFB(iv_aes), backend=default_backend())
        encryptor_aes = cipher_aes.encryptor()
        encrypted_data_aes = iv_aes + encryptor_aes.update(padded_data) + encryptor_aes.finalize()
        
        chacha_key = os.urandom(32)
        chacha = ChaCha20Poly1305(chacha_key)
        nonce = os.urandom(12)
        encrypted_data_chacha = nonce + chacha.encrypt(nonce, encrypted_data_aes, None)

        with open(file_path + ".enc", 'wb') as file:
            file.write(encrypted_data_chacha)
        
        with open(file_path + ".hash", 'w') as hash_file:
            hash_file.write(original_hash)
        
        os.remove(file_path)
        hide_file(file_path + ".enc")
        hide_file(file_path + ".hash")
        
        set_read_only(file_path + ".enc")
        set_read_only(file_path + ".hash")

        logging.info(f"File encrypted with double encryption: {file_path}")
    except Exception as e:
        logging.error(f"Error encrypting file with double encryption {file_path}: {e}")

def decrypt_file_double(file_path, key):
    try:
        unhide_file(file_path)
        remove_read_only(file_path)

        with open(file_path, 'rb') as file:
            encrypted_data_chacha = file.read()
        
        nonce = encrypted_data_chacha[:12]
        encrypted_data_aes = ChaCha20Poly1305(key).decrypt(nonce, encrypted_data_chacha[12:], None)

        iv_aes = encrypted_data_aes[:16]
        cipher_aes = Cipher(algorithms.AES(key), modes.CFB(iv_aes), backend=default_backend())
        decryptor_aes = cipher_aes.decryptor()
        padded_data = decryptor_aes.update(encrypted_data_aes[16:]) + decryptor_aes.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()

        with open(file_path[:-4], 'wb') as file:
            file.write(data)
        
        unhide_file(file_path[:-4] + ".hash")
        remove_read_only(file_path[:-4] + ".hash")

        with open(file_path[:-4] + ".hash", 'r') as hash_file:
            original_hash = hash_file.read().strip()
        
        os.remove(file_path)
        
        decrypted_hash = hash_file(file_path[:-4])
        if original_hash != decrypted_hash:
            logging.error(f"File integrity check failed for {file_path[:-4]}")
            raise ValueError(f"File integrity check failed for {file_path[:-4]}")
        
        os.remove(file_path[:-4] + ".hash")
        logging.info(f"File decrypted with double encryption: {file_path[:-4]}")
    except Exception as e:
        logging.error(f"Error decrypting file with double encryption {file_path}: {e}")

def update_password(folder_path, old_password, new_password):
    try:
        unhide_file(os.path.join(folder_path, 'salt.key'))
        remove_read_only(os.path.join(folder_path, 'salt.key'))

        with open(os.path.join(folder_path, 'salt.key'), 'rb') as salt_file:
            salt = salt_file.read()
        
        old_key = generate_key(old_password, salt)
        new_key = generate_key(new_password, salt)

        for root, _, files in os.walk(folder_path):
            for file in files:
                if file.endswith('.enc'):
                    file_path = os.path.join(root, file)
                    decrypt_file_double(file_path, old_key)
                    encrypt_file_double(file_path[:-4], new_key)

        logging.info(f"Password updated for folder: {folder_path}")
    except Exception as e:
        logging.error(f"Error updating password for folder {folder_path}: {e}")

def encrypt_folder(folder_path, password):
    try:
        salt = os.urandom(16)
        key = generate_key(password, salt)
        
        for root, _, files in os.walk(folder_path):
            for file in files:
                file_path = os.path.join(root, file)
                encrypt_file_double(file_path, key)
        
        with open(os.path.join(folder_path, 'salt.key'), 'wb') as salt_file:
            salt_file.write(salt)
        hide_file(os.path.join(folder_path, 'salt.key'))
        set_read_only(os.path.join(folder_path, 'salt.key'))

        logging.info(f"Folder encrypted: {folder_path}")

        # Start monitoring the folder for new files and folders
        monitor_thread = threading.Thread(target=monitor_folder, args=(folder_path, key))
        monitor_thread.daemon = True
        monitor_thread.start()

    except Exception as e:
        logging.error(f"Error encrypting folder {folder_path}: {e}")

def decrypt_folder(folder_path, password):
    try:
        unhide_file(os.path.join(folder_path, 'salt.key'))
        remove_read_only(os.path.join(folder_path, 'salt.key'))

        with open(os.path.join(folder_path, 'salt.key'), 'rb') as salt_file:
            salt = salt_file.read()

        key = generate_key(password, salt)

        for root, _, files in os.walk(folder_path):
            for file in files:
                if file.endswith('.enc'):
                    file_path = os.path.join(root, file)
                    decrypt_file_double(file_path, key)
        
        os.remove(os.path.join(folder_path, 'salt.key'))
        logging.info(f"Folder decrypted: {folder_path}")
    except Exception as e:
        logging.error(f"Error decrypting folder {folder_path}: {e}")

def set_read_only(file_path):
    try:
        sd = win32security.GetFileSecurity(file_path, win32security.DACL_SECURITY_INFORMATION)
        dacl = sd.GetSecurityDescriptorDacl()
        dacl.AddAccessAllowedAce(win32security.ACL_REVISION, win32security.FILE_GENERIC_READ, win32security.GetUserName())
        sd.SetSecurityDescriptorDacl(1, dacl, 0)
        win32security.SetFileSecurity(file_path, win32security.DACL_SECURITY_INFORMATION, sd)
    except pywintypes.error as e:
        logging.error(f"Error setting read-only attribute for {file_path}: {e}")

def remove_read_only(file_path):
    try:
        sd = win32security.GetFileSecurity(file_path, win32security.DACL_SECURITY_INFORMATION)
        dacl = sd.GetSecurityDescriptorDacl()
        dacl.DeleteAce(dacl.GetAceCount() - 1)
        sd.SetSecurityDescriptorDacl(1, dacl, 0)
        win32security.SetFileSecurity(file_path, win32security.DACL_SECURITY_INFORMATION, sd)
    except pywintypes.error as e:
        logging.error(f"Error removing read-only attribute for {file_path}: {e}")

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

def start_update_password():
    folder_path = folder_entry.get()
    old_password = old_password_entry.get()
    new_password = new_password_entry.get()
    if not folder_path or not old_password or not new_password:
        messagebox.showwarning("Input Error", "Please enter folder path, old password, and new password")
        return

    update_password(folder_path, old_password, new_password)
    messagebox.showinfo("Success", "Password updated successfully.")

def monitor_folder(folder_path, key):
    while True:
        for root, _, files in os.walk(folder_path):
            for file in files:
                file_path = os.path.join(root, file)
                if not file.endswith('.enc') and not file.endswith('.hash') and not os.path.isfile(file_path + ".enc"):
                    encrypt_file_double(file_path, key)
        time.sleep(5)

if platform.system() != "Windows":
    messagebox.showerror("OS Error", "This program only supports Windows OS")
    exit()

root = tk.Tk()
root.title("Folder Encryption Tool")

tk.Label(root, text="Folder Path:").grid(row=0, column=0, padx=10, pady=10)
folder_entry = tk.Entry(root, width=50)
folder_entry.grid(row=0, column=1, padx=10, pady=10)
tk.Button(root, text="Browse", command=select_folder).grid(row=0, column=2, padx=10, pady=10)

tk.Label(root, text="Password:").grid(row=1, column=0, padx=10, pady=10)
password_entry = tk.Entry(root, show="*", width=50)
password_entry.grid(row=1, column=1, padx=10, pady=10)

tk.Button(root, text="Encrypt Folder", command=start_encryption).grid(row=2, column=0, columnspan=3, padx=10, pady=10)
tk.Button(root, text="Decrypt Folder", command=start_decryption).grid(row=3, column=0, columnspan=3, padx=10, pady=10)

tk.Label(root, text="Old Password:").grid(row=4, column=0, padx=10, pady=10)
old_password_entry = tk.Entry(root, show="*", width=50)
old_password_entry.grid(row=4, column=1, padx=10, pady=10)

tk.Label(root, text="New Password:").grid(row=5, column=0, padx=10, pady=10)
new_password_entry = tk.Entry(root, show="*", width=50)
new_password_entry.grid(row=5, column=1, padx=10, pady=10)

tk.Button(root, text="Update Password", command=start_update_password).grid(row=6, column=0, columnspan=3, padx=10, pady=10)

root.mainloop()
