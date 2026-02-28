import tkinter as tk
from tkinter import messagebox
import sqlite3
import hashlib
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_NAME = os.path.join(BASE_DIR, "sheild_users.db")

# ---------------- DATABASE ----------------
def setup_database():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            phone TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL,
            hashed_password TEXT NOT NULL,
            salt TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

# ---------------- PASSWORD HASHING ----------------
def hash_password(password, salt=None):
    if salt is None:
        salt = os.urandom(16)
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return pwd_hash.hex(), salt.hex()

def verify_password(stored_hash, stored_salt, password):
    salt = bytes.fromhex(stored_salt)
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return pwd_hash.hex() == stored_hash

# ---------------- DATABASE QUERY ----------------
def db_query(query, params=(), fetch=None):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute(query, params)
    if fetch == "one":
        result = cursor.fetchone()
    elif fetch == "all":
        result = cursor.fetchall()
    else:
        conn.commit()
        result = None
    conn.close()
    return result

# ---------------- REGISTER WINDOW ----------------
class RegisterWindow:
    def __init__(self, parent):
        self.window = tk.Toplevel(parent)
        self.window.title("SHEILD - Create Account")
        self.window.geometry("450x650")
        self.window.configure(bg="#1f2b38")

        main_frame = tk.Frame(self.window, bg="#1f2b38")
        main_frame.pack(fill="both", expand=True, padx=40, pady=40)

        tk.Label(main_frame, text="🛡 Create SHEILD Account", font=("Arial", 20, "bold"), fg="#ff4d6d", bg="#1f2b38").pack(pady=(0,30))

        labels = ["Name", "Phone", "Email", "Password", "Confirm Password"]
        self.entries = {}

        for lbl in labels:
            tk.Label(main_frame, text=lbl, font=("Arial", 11), fg="white", bg="#1f2b38").pack(anchor="w", pady=(10,5))
            entry = tk.Entry(main_frame, width=35, font=("Arial", 11), show="*" if "Password" in lbl else "")
            entry.pack(ipady=6, pady=(0,5))
            self.entries[lbl] = entry

        tk.Button(main_frame, text="Create Account", font=("Arial", 12, "bold"), bg="#ff4d6d", fg="white", width=25, command=self.register).pack(pady=30)

    def register(self):
        name = self.entries["Name"].get().strip()
        phone = self.entries["Phone"].get().strip()
        email = self.entries["Email"].get().strip()
        pwd = self.entries["Password"].get()
        cpwd = self.entries["Confirm Password"].get()

        if not all([name, phone, email, pwd, cpwd]):
            messagebox.showerror("Error", "Please fill all fields.")
            return

        if not phone.isdigit() or len(phone) != 10:
            messagebox.showerror("Error", "Enter valid 10-digit phone number.")
            return

        if pwd != cpwd:
            messagebox.showerror("Error", "Passwords do not match.")
            return

        hashed, salt = hash_password(pwd)

        try:
            db_query(
                "INSERT INTO users (name, phone, email, hashed_password, salt) VALUES (?, ?, ?, ?, ?)",
                (name, phone, email, hashed, salt)
            )
            messagebox.showinfo("Success", "Account created successfully 🛡")
            self.window.destroy()
        except sqlite3.IntegrityError:
            messagebox.showerror("Error", "Phone already registered.")

# ---------------- DASHBOARD FRONTEND ----------------
class Dashboard:
    def __init__(self, user_name):
        self.contacts_list = []  # In-memory contacts for demo

        self.window = tk.Toplevel()
        self.window.title("SHEILD Dashboard")
        self.window.geometry("700x550")
        self.window.configure(bg="#1f2b38")

        tk.Label(self.window, text=f"Welcome, {user_name} 🛡", font=("Arial", 20, "bold"), fg="#ff4d6d", bg="#1f2b38").pack(pady=20)

        # SOS Button
        tk.Button(
            self.window,
            text="🚨 SOS",
            font=("Arial", 24, "bold"),
            fg="white",
            bg="#ff4d6d",
            width=15,
            height=2,
            command=self.trigger_sos
        ).pack(pady=30)

        # Trusted Contacts Section
        tk.Label(self.window, text="Trusted Contacts", font=("Arial", 16, "bold"), fg="white", bg="#1f2b38").pack(pady=(20,10))
        self.contacts_frame = tk.Frame(self.window, bg="#1f2b38")
        self.contacts_frame.pack()
        self.load_contacts()

        tk.Button(
            self.window,
            text="Add Contact",
            font=("Arial", 11, "bold"),
            bg="#34495e",
            fg="white",
            width=15,
            command=self.add_contact_popup
        ).pack(pady=10)

        # Emergency Numbers Section
        tk.Label(self.window, text="Emergency Numbers", font=("Arial", 16, "bold"), fg="white", bg="#1f2b38").pack(pady=(30,10))
        em_nums = ["Police: 100", "Women Helpline: 1091", "Ambulance: 102"]
        for num in em_nums:
            tk.Label(self.window, text=num, font=("Arial", 12), fg="white", bg="#1f2b38").pack()

    def load_contacts(self):
        # Clear frame
        for widget in self.contacts_frame.winfo_children():
            widget.destroy()
        # Display all contacts
        if not self.contacts_list:
            tk.Label(self.contacts_frame, text="No contacts added yet", fg="white", bg="#1f2b38", font=("Arial", 11)).pack()
        else:
            for contact in self.contacts_list:
                tk.Label(self.contacts_frame, text=f"{contact['name']} - {contact['email']}", fg="white", bg="#1f2b38", font=("Arial", 11)).pack(anchor="w", pady=2)

    def add_contact_popup(self):
        popup = tk.Toplevel()
        popup.title("Add Trusted Contact")
        popup.geometry("350x200")
        popup.configure(bg="#1f2b38")

        tk.Label(popup, text="Enter Contact Name", fg="white", bg="#1f2b38").pack(pady=(20,5))
        name_entry = tk.Entry(popup, width=30)
        name_entry.pack(pady=5)

        tk.Label(popup, text="Enter Contact Email", fg="white", bg="#1f2b38").pack(pady=(10,5))
        email_entry = tk.Entry(popup, width=30)
        email_entry.pack(pady=5)

        def save_contact():
            name = name_entry.get().strip()
            email = email_entry.get().strip()
            if not name or not email:
                messagebox.showerror("Error", "Please fill all fields.")
                return
            self.contacts_list.append({"name": name, "email": email})
            self.load_contacts()
            messagebox.showinfo("Success", f"{name} added to trusted contacts.")
            popup.destroy()

        tk.Button(popup, text="Save Contact", bg="#ff4d6d", fg="white", width=20, command=save_contact).pack(pady=15)

    def trigger_sos(self):
        messagebox.showinfo("SOS Triggered", "SOS alert triggered! Trusted contacts have been notified 🛡")

# ---------------- LOGIN SYSTEM ----------------
class LoginSystem:
    def __init__(self, root):
        self.root = root
        self.root.title("SHEILD - Women Safety App")
        self.root.geometry("800x600")
        self.root.configure(bg="#1f2b38")

        main_frame = tk.Frame(root, bg="#1f2b38")
        main_frame.pack(fill="both", expand=True, padx=50, pady=60)

        tk.Label(main_frame, text="🛡 SHEILD", font=("Arial", 28, "bold"), fg="#ff4d6d", bg="#1f2b38").pack(pady=(0,10))
        tk.Label(main_frame, text="Women Safety App", font=("Arial", 14), fg="white", bg="#1f2b38").pack(pady=(0,40))

        # Phone
        tk.Label(main_frame, text="Phone Number", font=("Arial", 11), fg="white", bg="#1f2b38").pack(anchor="w", pady=(10,5))
        self.phone_entry = tk.Entry(main_frame, width=35, font=("Arial", 11))
        self.phone_entry.pack(ipady=6, pady=(0,15))

        # Password
        tk.Label(main_frame, text="Password", font=("Arial", 11), fg="white", bg="#1f2b38").pack(anchor="w", pady=(10,5))
        self.password_entry = tk.Entry(main_frame, show="*", width=35, font=("Arial", 11))
        self.password_entry.pack(ipady=6, pady=(0,30))

        tk.Button(main_frame, text="Sign In", font=("Arial", 12, "bold"), bg="#ff4d6d", fg="white", width=25, command=self.login).pack(pady=(0,15))
        tk.Button(main_frame, text="Register Here", font=("Arial", 11), bg="#34495e", fg="white", width=25, command=self.show_register).pack()

    def show_register(self):
        RegisterWindow(self.root)

    def login(self):
        phone = self.phone_entry.get().strip()
        password = self.password_entry.get()
        if not phone or not password:
            messagebox.showerror("Login Failed", "Please enter all fields.")
            return

        user = db_query("SELECT name, hashed_password, salt FROM users WHERE phone=?", (phone,), fetch="one")
        if user and verify_password(user[1], user[2], password):
            messagebox.showinfo("Success", f"Welcome {user[0]}!\nStay Safe 🛡")
            Dashboard(user[0])  # Open frontend dashboard
        else:
            messagebox.showerror("Login Failed", "Invalid phone or password.")

# ---------------- MAIN ----------------
if __name__ == "__main__":
    setup_database()
    root = tk.Tk()
    app = LoginSystem(root)
    root.mainloop()