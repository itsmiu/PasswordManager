
import customtkinter as ctk
from tkinter import messagebox
from tkinter import simpledialog
from tkinter import ttk
import pyperclip
import hashlib
from database import create_table, add_password, get_passwords, delete_password, register_user, authenticate_user, get_user_id
from encryption import encrypt_password, decrypt_password
import string
import random

class PasswordManagerApp(ctk.CTk):

    def __init__(self):
        super().__init__()

        self.title("Password Manager")
        self.geometry("800x600")
        self.resizable(False, False)

        ctk.set_appearance_mode("dark")  # Dark mode
        ctk.set_default_color_theme("blue")

        self.username = None
        self.user_id = None
        self.master_password = None

        create_table()  # Ensure the tables are created before using the app

        self.create_widgets()

    def create_widgets(self):
        self.frame = ctk.CTkFrame(self)
        self.frame.pack(pady=20, padx=20, fill="both", expand=True)

        self.label = ctk.CTkLabel(self.frame, text="Password Manager", font=("Arial", 20))
        self.label.pack(pady=10)

        # Updated the table to remove the 'id' column
        self.table = ttk.Treeview(self.frame, columns=("name", "username", "password"), show="headings")
        self.table.heading("name", text="Name")
        self.table.heading("username", text="Username")
        self.table.heading("password", text="Password")
        self.table.column("name", width=200)
        self.table.column("username", width=200)
        self.table.column("password", width=200)
        self.table.pack(pady=10, padx=10)

        self.button_frame = ctk.CTkFrame(self.frame)
        self.button_frame.pack(pady=10)

        self.add_button = ctk.CTkButton(self.button_frame, text="Add Password", command=self.add_password)
        self.add_button.grid(row=0, column=0, padx=10)

        self.view_button = ctk.CTkButton(self.button_frame, text="View Password", command=self.view_password)
        self.view_button.grid(row=0, column=1, padx=10)

        self.delete_button = ctk.CTkButton(self.button_frame, text="Delete Password", command=self.delete_password)
        self.delete_button.grid(row=0, column=2, padx=10)

        self.generate_button = ctk.CTkButton(self.button_frame, text="Generate Password", command=self.generate_password)
        self.generate_button.grid(row=0, column=3, padx=10)

        self.login_or_register()

    def login_or_register(self):
        choice = messagebox.askyesno("Welcome", "Do you have an account? Click 'Yes' to login, 'No' to register.")
        if choice:
            self.login()
        else:
            self.register()

    def register(self):
        username = simpledialog.askstring("Register", "Enter a new username:")
        if not username:
            messagebox.showerror("Registration Failed", "Username cannot be empty.")
            self.quit()

        master_password = simpledialog.askstring("Register", "Enter a new master password:", show='*')
        if not master_password:
            messagebox.showerror("Registration Failed", "Master password cannot be empty.")
            self.quit()

        master_password_hash = hashlib.sha256(master_password.encode()).hexdigest()

        if register_user(username, master_password_hash):
            messagebox.showinfo("Registration Successful", "You have successfully registered!")
            self.username = username
            self.master_password = master_password
            self.user_id = get_user_id(username)
            self.load_passwords()  # Load the passwords after successful registration
        else:
            messagebox.showerror("Registration Failed", "Username already exists. Please try a different username.")
            self.register()

    def login(self):
        username = simpledialog.askstring("Login", "Enter your username:")
        if not username:
            messagebox.showerror("Login Failed", "Username cannot be empty.")
            self.quit()

        master_password = simpledialog.askstring("Login", "Enter your master password:", show='*')
        if not master_password:
            messagebox.showerror("Login Failed", "Master password cannot be empty.")
            self.quit()

        master_password_hash = hashlib.sha256(master_password.encode()).hexdigest()

        if authenticate_user(username, master_password_hash):
            messagebox.showinfo("Login Successful", f"Welcome back, {username}!")
            self.username = username
            self.master_password = master_password
            self.user_id = get_user_id(username)
            self.load_passwords()
        else:
            messagebox.showerror("Login Failed", "Incorrect username or master password. Please try again.")
            self.login()

    def add_password(self):
        # Gather all details in a single dialog flow
        name = simpledialog.askstring("Add Password", "Enter the name:")
        if name is None:
            return  # User canceled

        username = simpledialog.askstring("Add Password", "Enter the username:")
        if username is None:
            return  # User canceled

        password = simpledialog.askstring("Add Password", "Enter the password:", show='*')
        if password is None:
            return  # User canceled

        encrypted_password = encrypt_password(password, self.master_password)
        add_password(self.user_id, name, username, encrypted_password)
        self.load_passwords()

    def view_password(self):
        selected_item = self.table.selection()
        if not selected_item:
            messagebox.showinfo("View Password", "No item selected")
            return
        # Removed item_id from table item values
        encrypted_password = self.table.item(selected_item)["values"][2]
        decrypted_password = decrypt_password(encrypted_password, self.master_password)
        pyperclip.copy(decrypted_password)
        messagebox.showinfo("Password Copied", "Password copied to clipboard")

    def delete_password(self):
        selected_item = self.table.selection()
        if not selected_item:
            messagebox.showinfo("Delete Password", "No item selected")
            return

        # Get the internal ID of the selected item (to use in the database)
        item_id = self.table.index(selected_item[0])
        
        name = self.table.item(selected_item)["values"][0]  # Adjusted index due to ID removal

        # Confirm deletion with a warning message
        confirm = messagebox.askyesno(
            "Confirm Deletion",
            f"Are you sure you want to delete the password for '{name}'?",
            icon=messagebox.WARNING
        )

        if confirm:
            delete_password(item_id + 1)  # Adjust the item_id index when deleting
            self.load_passwords()
            messagebox.showinfo("Deleted", f"Password for '{name}' has been deleted successfully.")

    def generate_password(self):
        length = simpledialog.askinteger("Generate Password", "Enter the length:", minvalue=8, maxvalue=32)
        if not length:
            return
        characters = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(random.choice(characters) for i in range(length))
        pyperclip.copy(password)
        messagebox.showinfo("Generated Password", "Password copied to clipboard: " + password)

    def load_passwords(self):
        for item in self.table.get_children():
            self.table.delete(item)
        passwords = get_passwords(self.user_id)
        for idx, password in enumerate(passwords):
            # Exclude the ID from the table view
            self.table.insert("", "end", values=(password[2], password[3], password[4]))

if __name__ == "__main__":
    app = PasswordManagerApp()
    app.mainloop()
