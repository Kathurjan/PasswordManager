import tkinter as tk
from tkinter import simpledialog, messagebox, ttk
from password_manager import PasswordManager
import string
import random

class PasswordManagerGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.withdraw()  # Hide main window while getting master password

        # Prompt user for the master password
        self.master_password = simpledialog.askstring("Master Password", "Enter your master password:", show='*')
        if not self.master_password:
            messagebox.showerror("Error", "Master password is required!")
            exit()

        # Initialize password manager with logic class
        self.password_manager = PasswordManager(self.master_password)

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

    # Add a new password entry
    def add_password_entry(self):
        website = simpledialog.askstring("Input", "Enter website:")
        username = simpledialog.askstring("Input", "Enter username:")
        password = simpledialog.askstring("Input", "Enter password:")

        if not website or not username or not password:
            messagebox.showwarning("Input Error", "All fields are required!")
            return

        self.password_manager.add_password_entry(website, username, password)
        messagebox.showinfo("Success", "Password saved successfully.")

    # Retrieve an existing password entry
    def retrieve_password_entry(self):
        website = simpledialog.askstring("Input", "Enter website to retrieve:")

        if not website:
            messagebox.showwarning("Input Error", "Website is required!")
            return

        entry, decrypted_password = self.password_manager.retrieve_password_entry(website)
        if entry:
            messagebox.showinfo("Password Entry", f"Website: {entry['website']}\nUsername: {entry['username']}\nPassword: {decrypted_password}")
        else:
            messagebox.showerror("Not Found", "No entry found for the given website.")

    # Generate a secure password
    def generate_secure_password(self):
        length = 16
        characters = string.ascii_letters + string.digits + "!@#$%^&*()_-+=<>?"
        password = ''.join(random.choice(characters) for _ in range(length))

        # Display the password and provide a copy button
        password_window = tk.Toplevel(self.root)
        password_window.title("Generated Password")
        password_window.geometry("400x200")
        password_window.configure(bg="#2b2b2b")

        password_label = tk.Label(password_window, text=f"Generated Password: {password}", font=("Helvetica", 14), fg="#f0f0f0", bg="#2b2b2b")
        password_label.pack(pady=20)

        def copy_to_clipboard():
            self.root.clipboard_clear()
            self.root.clipboard_append(password)
            self.root.update()  # Keep the clipboard content
            messagebox.showinfo("Copied", "Password copied to clipboard")

        copy_button = ttk.Button(password_window, text="Copy Password", command=copy_to_clipboard)
        copy_button.pack(pady=10)


if __name__ == "__main__":
    PasswordManagerGUI()
