import tkinter as tk
from tkinter import messagebox
from user_behavior_simulator import UserBehaviorSimulator
from datetime import datetime

class LoginGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Login Simulation")
        self.root.geometry("600x300")
        self.user_simulator = UserBehaviorSimulator()
        self.logged_in = False
        self.failed_attempts = 0
        self.create_user_panel()
        self.create_admin_panel()

    def create_user_panel(self):
        user_panel = tk.Frame(self.root)
        user_panel.pack(side="left", padx=10, pady=10)

        label_username = tk.Label(user_panel, text="Username:")
        label_username.grid(row=0, column=0, padx=5, pady=5)
        self.entry_username = tk.Entry(user_panel)
        self.entry_username.grid(row=0, column=1, padx=5, pady=5)

        label_password = tk.Label(user_panel, text="Password:")
        label_password.grid(row=1, column=0, padx=5, pady=5)
        self.entry_password = tk.Entry(user_panel, show="*")
        self.entry_password.grid(row=1, column=1, padx=5, pady=5)

        self.button_login = tk.Button(user_panel, text="Login", command=self.login)
        self.button_login.grid(row=2, column=0, columnspan=2, padx=5, pady=5)

    def create_admin_panel(self):
        admin_panel = tk.Frame(self.root)
        admin_panel.pack(side="right", padx=10, pady=10)

        label_admin_options = tk.Label(admin_panel, text="Administrator Panel")
        label_admin_options.pack()

        button_view_report = tk.Button(admin_panel, text="View Report", command=self.user_simulator.generate_report)
        button_view_report.pack(pady=5)

        button_view_graph = tk.Button(admin_panel, text="View Graph", command=self.view_graph)
        button_view_graph.pack(pady=5)

        label_password_file = tk.Label(admin_panel, text="Password File:")
        label_password_file.pack()
        button_open_password_file = tk.Button(admin_panel, text="Open Password File", command=self.open_password_file)
        button_open_password_file.pack(pady=5)

    def login(self):
        username = self.entry_username.get()
        password = self.entry_password.get()

        credentials = read_credentials("passwords.txt")

        if credentials and username in credentials and credentials[username] == password:
            self.user_simulator.simulate_login()
            messagebox.showinfo("Login Successful", "Welcome!")
            self.user_simulator.reset_login_attempts()
            self.entry_username.delete(0, tk.END)
            self.entry_password.delete(0, tk.END)
            self.logged_in = True
        else:
            self.user_simulator.simulate_failed_login()
            messagebox.showerror("Login Failed", "Incorrect Username or Password!")
            self.user_simulator.record_credentials(username, password)
            self.failed_attempts += 1
            if self.failed_attempts >= 3:
                self.button_login.config(state=tk.DISABLED)
                messagebox.showwarning("No More Attempts", "You have reached the maximum number of login attempts.")

    def view_graph(self):
        try:
            img = tk.PhotoImage(file="login_activity.png")
            graph_window = tk.Toplevel(self.root)
            graph_window.title("Login Activity Graph")
            graph_label = tk.Label(graph_window, image=img)
            graph_label.image = img
            graph_label.pack()
        except Exception as e:
            print("Error:", e)
            messagebox.showerror("Error", "Failed to load graph.")

    def open_password_file(self):
        try:
            password_file_path = "passwords.txt"
            with open(password_file_path, "r") as file:
                password_data = file.read()
            password_window = tk.Toplevel(self.root)
            password_window.title("Password File")
            password_text = tk.Text(password_window)
            password_text.insert(tk.END, password_data)
            password_text.pack()
        except Exception as e:
            print("Error:", e)
            messagebox.showerror("Error", "Failed to open password file.")

def read_credentials(file_path):
    credentials = {}
    try:
        with open(file_path, "r") as file:
            for line in file:
                line = line.strip()
                if line:
                    parts = line.split(':')
                    if len(parts) == 2:
                        username, password = parts
                        credentials[username] = password
                    else:
                        print(f"Ignore malformed line: {line}")
    except FileNotFoundError:
        print("Password file not found.")
    return credentials
