from tkinter import Tk, Frame, Label, Entry, Button, END
from tkinter import ttk, messagebox
from cryptography.fernet import Fernet
import random
import string
import os

# File Encryption Functions
def encrypt_file(file_path, key):
    fernet = Fernet(key)
    with open(file_path, "rb") as file:
        file_data = file.read()
    encrypted_data = fernet.encrypt(file_data)
    with open(file_path, "wb") as file:
        file.write(encrypted_data)

def decrypt_file(file_path, key):
    fernet = Fernet(key)
    with open(file_path, "rb") as file:
        encrypted_data = file.read()
    decrypted_data = fernet.decrypt(encrypted_data)
    with open(file_path, "wb") as file:
        file.write(decrypted_data)

# Password Encryption Function
def encrypt_password(password, key):
    fernet = Fernet(key)
    return fernet.encrypt(password.encode())

# Password Generator
def generate_password(length=16):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for _ in range(length))

# Generate Password Tab
def generate_password_tab(parent):
    frame = Frame(parent, bg="#1C1C1C")
    frame.pack(pady=30, fill="both", expand=True)

    Label(frame, text="Generated Password:", font=("Comic Sans MS", 14), fg="white", bg="#1C1C1C").pack(pady=10)
    password_box = Entry(frame, font=("Comic Sans MS", 14), width=40, justify="center", bg="#333333", fg="white", relief="flat")
    password_box.pack(pady=5)

    def generate_new_password():
        new_password = generate_password()
        password_box.delete(0, END)
        password_box.insert(0, new_password)

    generate_new_password()  # Generate password on load

    # Button with hover effect
    def on_enter(event):
        generate_button.config(bg="#444444")

    def on_leave(event):
        generate_button.config(bg="#555555")

    generate_button = Button(frame, text="Generate Another", command=generate_new_password,
                              font=("Comic Sans MS", 14), bg="#555555", fg="white", relief="flat")
    generate_button.pack(pady=10)
    generate_button.bind("<Enter>", on_enter)
    generate_button.bind("<Leave>", on_leave)

# Store Password Tab
def store_password_tab(parent, key):
    frame = Frame(parent, bg="#1C1C1C")
    frame.pack(pady=30, fill="both", expand=True)

    # Center alignment for Store tab
    Label(frame, text="Website:", font=("Arial", 12, "italic"), fg="white", bg="#1C1C1C").grid(row=0, column=0, padx=5, pady=10, sticky="e")
    website_entry = Entry(frame, font=("Arial", 12, "italic"), width=35, bg="#333333", fg="white", relief="flat")
    website_entry.grid(row=0, column=1, padx=5, pady=10, sticky="w")

    Label(frame, text="Username:", font=("Arial", 12, "italic"), fg="white", bg="#1C1C1C").grid(row=1, column=0, padx=5, pady=10, sticky="e")
    username_entry = Entry(frame, font=("Arial", 12, "italic"), width=35, bg="#333333", fg="white", relief="flat")
    username_entry.grid(row=1, column=1, padx=5, pady=10, sticky="w")

    Label(frame, text="Password:", font=("Arial", 12, "italic"), fg="white", bg="#1C1C1C").grid(row=2, column=0, padx=5, pady=10, sticky="e")
    password_entry = Entry(frame, font=("Arial", 12, "italic"), width=35, bg="#333333", fg="white", relief="flat")
    password_entry.grid(row=2, column=1, padx=5, pady=10, sticky="w")

    def save_password():
        if os.path.exists("passwords.txt"):
            decrypt_file("passwords.txt", key)  # Decrypt file for writing
        website = website_entry.get()
        username = username_entry.get()
        password = password_entry.get()
        
        encrypted_password = encrypt_password(password, key)  # Corrected function call

        with open("passwords.txt", "a") as file:
            file.write(f"{website},{username},{encrypted_password.decode()}\n")
        
        encrypt_file("passwords.txt", key)  # Re-encrypt file after writing
        messagebox.showinfo("Success", "Password stored successfully!")
        website_entry.delete(0, END)
        username_entry.delete(0, END)
        password_entry.delete(0, END)

    # Button with hover effect
    def on_enter(event):
        save_button.config(bg="#444444")

    def on_leave(event):
        save_button.config(bg="#555555")

    save_button = Button(frame, text="Save Password", command=save_password,
                         font=("Arial", 12, "italic"), bg="#555555", fg="white", relief="flat")
    save_button.grid(row=3, column=0, columnspan=2, pady=20)
    save_button.bind("<Enter>", on_enter)
    save_button.bind("<Leave>", on_leave)

# Retrieve Password Tab
def retrieve_password_tab(parent, key):
    frame = Frame(parent, bg="#1C1C1C")
    frame.pack(pady=30, fill="both", expand=True)

    # Center alignment for Retrieve tab
    Label(frame, text="Website:", font=("Times New Roman", 13), fg="white", bg="#1C1C1C").grid(row=0, column=0, padx=5, pady=10, sticky="e")
    website_entry = Entry(frame, font=("Times New Roman", 13), width=35, bg="#333333", fg="white", relief="flat")
    website_entry.grid(row=0, column=1, padx=5, pady=10, sticky="w")

    result_label = Label(frame, text="", fg="light green", font=("Times New Roman", 13), bg="#1C1C1C")
    result_label.grid(row=1, column=0, columnspan=2, pady=10)

    def retrieve_password():
        if os.path.exists("passwords.txt"):
            decrypt_file("passwords.txt", key)  # Decrypt file for reading
        website = website_entry.get()
        try:
            with open("passwords.txt", "r") as file:
                for line in file:
                    stored_website, stored_username, stored_encrypted_password = line.strip().split(",")
                    if stored_website == website:
                        decrypted_password = Fernet(key).decrypt(stored_encrypted_password.encode()).decode()
                        result_label.config(text=f"Username: {stored_username}\nPassword: {decrypted_password}")
                        encrypt_file("passwords.txt", key)  # Re-encrypt file after reading
                        return
        except FileNotFoundError:
            result_label.config(text="No passwords found.")
        encrypt_file("passwords.txt", key)  # Re-encrypt file
        result_label.config(text="No password found for this website.")

    # Button with hover effect
    def on_enter(event):
        retrieve_button.config(bg="#444444")

    def on_leave(event):
        retrieve_button.config(bg="#555555")

    retrieve_button = Button(frame, text="Retrieve Password", command=retrieve_password,
                             font=("Times New Roman", 13), bg="#555555", fg="white", relief="flat")
    retrieve_button.grid(row=2, column=0, columnspan=2, pady=20)
    retrieve_button.bind("<Enter>", on_enter)
    retrieve_button.bind("<Leave>", on_leave)

# Load or Generate Encryption Key
try:
    with open("key.key", "rb") as key_file:
        key = key_file.read()
except FileNotFoundError:
    key = Fernet.generate_key()
    with open("key.key", "wb") as key_file:
        key_file.write(key)

# Ensure Password File is Initially Encrypted
if os.path.exists("passwords.txt"):
    encrypt_file("passwords.txt", key)

# Main GUI Initialization
app = Tk()
app.title("Securepass - Password Manager")
app.geometry("700x500")
app.configure(bg="#1C1C1C")

# Use a Modern Theme
style = ttk.Style()
style.theme_use("clam")
style.configure("TNotebook.Tab", font=("Arial", 16, "bold"), padding=[20, 10])

# Create Tabs
notebook = ttk.Notebook(app)
generate_tab = Frame(notebook, bg="#1C1C1C")
store_tab = Frame(notebook, bg="#1C1C1C")
retrieve_tab = Frame(notebook, bg="#1C1C1C")

notebook.add(generate_tab, text="Generate")
notebook.add(store_tab, text="Store")
notebook.add(retrieve_tab, text="Retrieve")
notebook.pack(expand=True, fill="both")

# Initialize Tabs
generate_password_tab(generate_tab)
store_password_tab(store_tab, key)
retrieve_password_tab(retrieve_tab, key)

# Run the App
app.mainloop()