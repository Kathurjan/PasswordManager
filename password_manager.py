import json
import os
import random
import string
import base64
import tkinter as tk
from tkinter import simpledialog, messagebox, ttk
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import secrets
import getpass

vault_file_path = "vault.json"
salt_file_path = "salt.bin"

class PasswordManager:
    def __init__(self):
        self.master_key = None
        self.salt = self.load_or_generate_salt()
        self.root = tk.Tk()
        self.root.withdraw()  # Hide main window while getting master password

        # Prompt user for the master password, which is used to derive the encryption key
        self.master_password = simpledialog.askstring("Master Password", "Enter your master password:", show='*')
        if not self.master_password:
            messagebox.showerror("Error", "Master password is required!")
            exit()

        # Derive the master key from the provided password
        self.master_key = self.derive_key(self.master_password)

        # Show the main window again after master password verification
        self.root.deiconify()
        self.root.title("Password Manager")
        self.root.geometry("500x400")
        self.root.configure(bg="#2b2b2b")

        # Style configuration for buttons and labels
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TButton", font=("Helvetica", 12), padding=10, background="#3c3f41", foreground="white")
        style.map("TButton",
                  foreground=[("active", "#f0f0f0")],
                  background=[("active", "#5a5c5e")])

        header = tk.Label(self.root, text="Password Manager", font=("Helvetica", 18, "bold"), fg="#f0f0f0", bg="#2b2b2b")
        header.pack(pady=20)

        # Add password entry button
        self.add_button = ttk.Button(self.root, text="Add Password Entry", command=self.add_password_entry)
        self.add_button.pack(pady=10)

        # Retrieve password entry button
        self.retrieve_button = ttk.Button(self.root, text="Retrieve Password Entry", command=self.retrieve_password_entry)
        self.retrieve_button.pack(pady=10)

        # Generate secure password button
        self.generate_button = ttk.Button(self.root, text="Generate Secure Password", command=self.generate_secure_password)
        self.generate_button.pack(pady=10)

        self.root.mainloop()

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




if __name__ == "__main__":
    PasswordManager()


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

    # Add a new password entry for a given website, username, and password
    def add_password_entry(self):
        website = simpledialog.askstring("Input", "Enter website:")
        username = simpledialog.askstring("Input", "Enter username:")
        password = simpledialog.askstring("Input", "Enter password:")

        if not website or not username or not password:
            messagebox.showwarning("Input Error", "All fields are required!")
            return

        # Encrypt the password before saving
        encrypted_password = self.encrypt(password)
        entry = {"website": website, "username": username, "password": encrypted_password}
        entries = self.get_entries_from_vault()
        entries.append(entry)
        self.save_entries_to_vault(entries)
        messagebox.showinfo("Success", "Password saved successfully.")

    # Retrieve an existing password entry for a given website
    def retrieve_password_entry(self):
        website = simpledialog.askstring("Input", "Enter website to retrieve:")

        if not website:
            messagebox.showwarning("Input Error", "Website is required!")
            return

        entries = self.get_entries_from_vault()
        for entry in entries:
            if entry["website"] == website:
                # Decrypt the stored password
                decrypted_password = self.decrypt(entry["password"])
                if decrypted_password:
                    messagebox.showinfo("Password Entry", f"Website: {entry['website']}\nUsername: {entry['username']}\nPassword: {decrypted_password}")
                else:
                    messagebox.showerror("Error", "Failed to decrypt password. The data might be corrupted.")
                return

        messagebox.showerror("Not Found", "No entry found for the given website.")