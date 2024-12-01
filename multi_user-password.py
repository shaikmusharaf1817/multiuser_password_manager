import tkinter as tk
from tkinter import messagebox, simpledialog
from tkinter import ttk
import os
import json
from cryptography.fernet import Fernet

def generate_key():
    return Fernet.generate_key()

def encrypt_password(password, key):
    fernet = Fernet(key)
    return fernet.encrypt(password.encode())

def decrypt_password(encrypted_password, key):
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_password).decode()


def get_user_data_file():
    app_data_directory="C:/vijaya/APP project"
    if not os.path.exists(app_data_directory):
        os.makedirs(app_data_directory)
    return os.path.join(app_data_directory, "users.json")


USER_DATA_FILE = get_user_data_file()


def load_user_data():
    if not os.path.exists(USER_DATA_FILE):
        print("Creating an empty JSON file for user data...")
        with open(USER_DATA_FILE, 'w') as f:
            json.dump({}, f)  # Initialize with an empty JSON object
    with open(USER_DATA_FILE, 'r') as f:
        return json.load(f)


def save_user_data(data):
    with open(USER_DATA_FILE, 'w') as f:
        json.dump(data, f, indent=4)

class PasswordManagerApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Passkeeper")
        self.master.geometry("700x800")
        self.master.configure(bg="gray1")  # Light background for a modern look

        # Apply custom style for ttk widgets
        self.style = ttk.Style()
        self.style.configure("Treeview",
                             background="gray1", 
                             foreground="#333333", 
                             rowheight=25, 
                             fieldbackground="gray1",
                             font=("Helvetica", 12))
        self.style.map("Treeview", background=[("selected", "gray12")])

        self.style.configure("Treeview.Heading", 
                             background="gray12", 
                             foreground="#333333", 
                             font=("Helvetica", 13, "bold"))

        # Style for buttons
        self.style.configure("TButton",
                             background="#00ACC1",
                             foreground="white",
                             font=("Helvetica", 12, "bold"),
                             padding=5)

        self.user_data = load_user_data()
        self.current_user = None

        self.login_frame = self.create_login_frame()
        self.login_frame.pack(expand=True, padx=40, pady=40)

        self.password_frame = self.create_password_frame()

    def create_login_frame(self):
        frame = tk.Frame(self.master, bg="gray12", padx=20, pady=20)
        frame.place(relx=0.5, rely=0.5, anchor="center")

        header = tk.Label(frame, text="Password Manager", bg="gray12", font=("Helvetica", 28, "bold"), fg="white")
        header.pack(pady=(10, 20))
        username_label = tk.Label(frame, text="Username", bg="gray12", font=("Helvetica", 12), fg="white")
        username_label.pack(pady=(5, 0))
        self.username_entry = tk.Entry(frame, width=30, font=("Helvetica", 12), highlightthickness=1, relief="solid", bd=0)
        self.username_entry.insert(0, "Username")
        self.username_entry.bind("<FocusIn>", lambda e: self.username_entry.delete(0, 'end'))
        self.username_entry.pack(pady=(5, 10), ipady=8)

        password_label = tk.Label(frame, text="Password", bg="gray12", font=("Helvetica", 12), fg="white")
        password_label.pack(pady=(5, 0))
        self.password_entry = tk.Entry(frame, width=30, font=("Helvetica", 12), highlightthickness=1, relief="solid", bd=0, show="*")
        self.password_entry.insert(0, "password")
        self.password_entry.bind("<FocusIn>", lambda e: self.password_entry.delete(0, 'end'))
        self.password_entry.pack(pady=(5, 10), ipady=8)

        login_button = tk.Button(frame, text="Log In", bg="#3897f0", fg="white", width=25, height=2, relief="flat", command=self.login)
        login_button.bind("<Enter>", lambda e: login_button.config(background="green"))
        login_button.bind("<Leave>", lambda e: login_button.config(background="deepskyblue"))
        login_button.pack(pady=(20, 10))

        or_frame = tk.Frame(frame, bg="gray12")
        or_frame.pack(pady=10)
        tk.Label(or_frame, text="–––––––––", bg="gray12", fg="#BDBDBD").grid(row=0, column=0)
        tk.Label(or_frame, text=" OR ", bg="gray12", fg="#BDBDBD", font=("Helvetica", 10)).grid(row=0, column=1)
        tk.Label(or_frame, text="–––––––––", bg="gray12", fg="#BDBDBD").grid(row=0, column=2)

        signup_button = tk.Button(frame, text="Create Account", bg="#3897f0", fg="white", width=25, height=2, relief="flat", command=self.signup)
        signup_button.bind("<Enter>", lambda e: signup_button.config(background="#00c04b"))
        signup_button.bind("<Leave>", lambda e: signup_button.config(background="#3897f0"))
        signup_button.pack(pady=(10, 20))

        return frame

    def create_password_frame(self):
        frame = tk.Frame(self.master, bg="gray12",padx=40,pady=30)

        password_label = tk.Label(frame, text="Your Passwords", font=("Helvetica", 24, 'bold'), bg="gray12", fg="white")
        password_label.pack(pady=20)

        # Search Bar
        search_frame = tk.Frame(frame, bg="gray12")
        search_frame.pack(pady=10)

        search_label = tk.Label(search_frame, text="Search: ", bg="gray12", font=("Helvetica", 12,'bold'), fg="white")
        search_label.pack(side=tk.LEFT)

        self.search_entry = ttk.Entry(search_frame, width=35, font=("Helvetica", 12))  # Using ttk.Entry for modern look
        self.search_entry.pack(side=tk.LEFT, padx=10)
        style = ttk.Style()
        style.configure("Custom.TButton", foreground="black", font=("Arial", 12))
        search_button = ttk.Button(search_frame, text="Search", command=self.search_passwords, style="Custom.TButton")
        search_button.pack(side=tk.LEFT)
        style.configure("Treeview",
                    background="white",
                    foreground="black",
                    rowheight=25,
                    fieldbackground="gray12",
                    font=("Helvetica", 12))
        style.map("Treeview", background=[("selected", "gray12")]) 

        # Create a frame for the Treeview and the scrollbar
        table_frame = tk.Frame(frame, bg="#F7F7F7")
        table_frame.pack(pady=20, fill=tk.BOTH, expand=True)

        # Scrollbar
        self.scrollbar = ttk.Scrollbar(table_frame)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        # Create a Treeview table with scrollbar
        columns = ("Platform", "UserID", "Password")
        self.password_table = ttk.Treeview(table_frame, columns=columns, show="headings", height=5, yscrollcommand=self.scrollbar.set)
        self.password_table.heading("Platform", text="Platform")
        self.password_table.heading("UserID", text="User ID")
        self.password_table.heading("Password", text="Password")

        # Center align the text in the columns
        for col in columns:
            self.password_table.column(col, anchor="center", width=350)

        self.password_table.pack(pady=15, fill=tk.BOTH, expand=True)
        self.scrollbar.config(command=self.password_table.yview)

        # Add buttons below the table
        button_frame = tk.Frame(frame, bg="gray12")
        button_frame.pack(pady=20)
        style = ttk.Style()
        style.configure("Custom.TButton", foreground="black", font=("Arial", 12))


        add_password_button = ttk.Button(button_frame, text="Add New Password", command=self.add_password, style="Custom.TButton")
    
        add_password_button.pack(side=tk.LEFT, padx=15)

        delete_password_button = ttk.Button(button_frame, text="Delete Selected Password", command=self.delete_password, style="Custom.TButton")
        delete_password_button.pack(side=tk.LEFT, padx=15)

        change_password_button = ttk.Button(button_frame, text="Change Password", command=self.change_password, style="Custom.TButton")
        
        change_password_button.pack(side=tk.LEFT, padx=15)

        logout_button = ttk.Button(button_frame, text="Logout", command=self.logout, style="Custom.TButton")
        
        logout_button.pack(side=tk.LEFT, padx=15)

        return frame
    def on_row_click(self, event):
        
    # Clear existing tags to remove previous highlights
        for item in self.password_table.get_children():
           self.password_table.item(item, tags=())

    # Get the clicked item and apply the 'clicked' tag
        selected_item = self.password_table.identify_row(event.y)
        if selected_item:
             self.password_table.item(selected_item, tags=("clicked",))

    def delete_password(self):
        selected_item = self.password_table.selection()  # Get selected item in the Treeview
        if selected_item:
            platform_name = self.password_table.item(selected_item, 'values')[0]  # Get platform name
        # Delete from user_data
        if platform_name in self.user_data[self.current_user]['passwords']:
            del self.user_data[self.current_user]['passwords'][platform_name]
            save_user_data(self.user_data)
            self.refresh_password_list()  # Refresh the table view
            messagebox.showinfo("Success", "Password deleted successfully.")
        else:
            messagebox.showwarning("Warning", "Please select a password to delete.")

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        if username in self.user_data and self.user_data[username]['password'] == password:
            self.current_user = username
            self.login_frame.pack_forget()
            self.password_frame.pack(expand=True)
            self.refresh_password_list()
        else:
            messagebox.showerror("Error", "Invalid username or password")

    def signup(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        if not username or not password:
            messagebox.showerror("Error", "Username and password cannot be empty.")
            return
        if not username[0].isalpha() or len(password) < 7:
            messagebox.showerror("Error", "Username must start with a letter, and password must be at least 7 characters.")
            return
        if username in self.user_data:  
            messagebox.showerror("Error", "User already exists")
        else:
            key = generate_key()
            self.user_data[username] = {
                'password': password,
                'key': key.decode(),
                'passwords': {}
            }
            save_user_data(self.user_data)
            messagebox.showinfo("Success", "User created successfully")

    def add_password(self):
        platform_name = simpledialog.askstring("Input", "Enter Platform Name:", parent=self.master)
        user_id = simpledialog.askstring("Input", "Enter User ID:", parent=self.master)
        password = simpledialog.askstring("Input", "Enter Password:", parent=self.master)
        if not platform_name or not user_id or not password:
            messagebox.showwarning("Warning", "All fields must be filled out.")
            return
        key = self.user_data[self.current_user]['key'].encode()
        encrypted_password = encrypt_password(password, key)

        self.user_data[self.current_user]['passwords'][platform_name.upper()] = {
            'user_id': user_id,
            'password': encrypted_password.decode()
        }
        save_user_data(self.user_data)
        self.refresh_password_list()

    def search_passwords(self):
        search_query = self.search_entry.get()
        self.refresh_password_list(search_query)

    def refresh_password_list(self, search_query=""):
        # Clear the table first
        for item in self.password_table.get_children():
            self.password_table.delete(item)

        key = self.user_data[self.current_user]['key'].encode()
        for platform, creds in self.user_data[self.current_user]['passwords'].items():
            if search_query.lower() in platform.lower():
                decrypted_password = decrypt_password(creds['password'].encode(), key)
                self.password_table.insert("", "end", values=(platform, creds['user_id'], decrypted_password))

    def change_password(self):
        current_password = simpledialog.askstring("Change Password", "Enter Current Password:", show='*')
        if current_password == self.user_data.get(self.current_user, {}).get('password'):
            new_password = simpledialog.askstring("Change Password", "Enter New Password:", show='*')
            confirm_password = simpledialog.askstring("Change Password", "Confirm New Password:", show='*')
            if new_password and new_password == confirm_password and len(new_password) >= 7:
                self.user_data[self.current_user]['password'] = new_password
                save_user_data(self.user_data)
                messagebox.showinfo("Success", "Password changed successfully.")
            else:
                messagebox.showerror("Error", "New passwords do not match or are too short.")
        else:
            messagebox.showerror("Error", "Incorrect current password.")

    def logout(self):
        self.password_frame.pack_forget()
        self.login_frame.pack(expand=True, padx=40, pady=40)

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManagerApp(root)
    root.mainloop()


