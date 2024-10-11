import json
import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import secrets

vault_file_path = "vault.json"
salt_file_path = "salt.bin"

class PasswordManager:
    def __init__(self, master_password):
        self.master_password = master_password
        self.master_key = None
        self.salt = self.load_or_generate_salt()
        self.master_key = self.derive_key(master_password)

    # Load salt from file if it exists, otherwise generate a new salt
    def load_or_generate_salt(self):
        if os.path.exists(salt_file_path):
            with open(salt_file_path, "rb") as file:
                return file.read()
        else:
            new_salt = os.urandom(16)
            with open(salt_file_path, "wb") as file:
                file.write(new_salt)
            return new_salt

    # Derive the encryption key from the master password using PBKDF2
    def derive_key(self, password):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,  # High iteration count for computational cost against brute-force attacks
            backend=default_backend()
        )
        return kdf.derive(password.encode())

    # Add a new password entry
    def add_password_entry(self, website, username, password):
        encrypted_password = self.encrypt(password)
        encrypted_webiste = self.encrypt(website)
        encrypted_username = self.encrypt(username)
        entry = {"website": encrypted_webiste, "username": encrypted_username, "password": encrypted_password}
        entries = self.get_entries_from_vault()
        entries.append(entry)
        self.save_entries_to_vault(entries)

    # Retrieve an existing password entry
    def retrieve_password_entry(self, website):
        entries = self.get_entries_from_vault()
        for entry in entries:
            if self.decrypt(entry["website"]) == website:
                return entry, self.decrypt(entry["password"]), self.decrypt(entry["username"]), self.decrypt(entry["website"])
        return None, None

    # Encrypt the given plain text using AES in CFB mode
    def encrypt(self, plain_text):
        iv = os.urandom(16)  # Generate a random initialization vector (IV)
        cipher = Cipher(algorithms.AES(self.master_key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_text = encryptor.update(plain_text.encode()) + encryptor.finalize()
        return base64.b64encode(iv + encrypted_text).decode()  # Encode IV + encrypted text as base64

    # Decrypt the given cipher text using AES in CFB mode
    def decrypt(self, cipher_text):
        try:
            decoded_data = base64.b64decode(cipher_text)
            iv = decoded_data[:16]  # Extract the IV from the decoded data
            encrypted_text = decoded_data[16:]
            cipher = Cipher(algorithms.AES(self.master_key), modes.CFB(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_text = decryptor.update(encrypted_text) + decryptor.finalize()
            return decrypted_text.decode()
        except (ValueError, UnicodeDecodeError) as e:
            print(f"Decryption error: {e}")
            return None

    # Retrieve all entries from the password vault (stored in JSON format)
    def get_entries_from_vault(self):
        if os.path.exists(vault_file_path):
            with open(vault_file_path, "r") as file:
                return json.load(file)
        return []

    # Save all entries to the password vault (in JSON format)
    def save_entries_to_vault(self, entries):
        with open(vault_file_path, "w") as file:
            json.dump(entries, file, indent=4)
