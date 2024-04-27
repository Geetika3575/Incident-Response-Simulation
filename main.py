import tkinter as tk
from tkinter import messagebox
from datetime import datetime, timedelta
import threading
import time
import requests
import matplotlib.pyplot as plt
from playsound import playsound  # Import playsound for playing sound

# Define a class to manage user behavior simulation
class UserBehaviorSimulator:
    def __init__(self):
        self.login_attempts = 0
        self.failed_login_attempts = 0
        self.used_usernames = set()
        self.used_passwords = set()
        self.locked_users = set()
        self.incidents = []

        # Data for visualization
        self.login_timestamps = []
        self.failed_login_timestamps = []
        self.alert_threshold = 3  # Updated threshold for failed login attempts
        self.lock_duration = timedelta(hours=3)  # Duration to lock user account

    def simulate_login(self):
        self.login_attempts += 1
        self.login_timestamps.append(datetime.now())

    def simulate_failed_login(self):
        self.failed_login_attempts += 1
        self.failed_login_timestamps.append(datetime.now())

    def record_credentials(self, username, password):
        self.used_usernames.add(username)
        self.used_passwords.add(password)

    def reset_login_attempts(self):
        self.login_attempts = 0
        self.failed_login_attempts = 0

    def generate_report(self):
        # Generate visualization before generating the report
        self.generate_visualization()

        # Save incident report
        report_filename = "incident_report.txt"
        with open(report_filename, "w") as report_file:
            report_file.write(f"Report generated at: {datetime.now()}\n")
            report_file.write(f"Total Login Attempts: {self.login_attempts}\n")
            report_file.write(f"Total Failed Login Attempts: {self.failed_login_attempts}\n")
            report_file.write("Used Usernames:\n")
            for username in self.used_usernames:
                report_file.write(f"- {username}\n")
            report_file.write("Used Passwords:\n")
            for password in self.used_passwords:
                report_file.write(f"- {password}\n")
            report_file.write("\nIncidents:Brute Force Attack\n")
            for incident in self.incidents:
                report_file.write(f"- {incident}\n")
        return report_filename

    def generate_visualization(self):
        # Create a simple visualization using Matplotlib
        plt.figure(figsize=(10, 6))
        plt.plot(self.login_timestamps, label="Successful Logins", marker='o')
        plt.plot(self.failed_login_timestamps, label="Failed Logins", marker='x')
        plt.xlabel("Time")
        plt.ylabel("Login Attempts")
        plt.title("Login Activity Over Time")
        plt.legend()
        plt.grid(True)
        plt.xticks(rotation=45)
        plt.tight_layout()
        visualization_filename = "login_activity.png"
        plt.savefig(visualization_filename)  # Save the plot as an image
        plt.close()

    def add_incident(self, timestamp, ip_address, username, action, affected_user=None, response=None):
        incident_details = f"{timestamp} - IP: {ip_address}, Username: {username}, Action: {action}"
        if affected_user:
            incident_details += f", Affected User: {affected_user}"
        if response:
            incident_details += f", Response: {response}"
        self.incidents.append(incident_details)

    def lock_user_account(self, username):
        # Lock the user account for a specified duration
        self.locked_users.add(username)
        unlock_time = datetime.now() + self.lock_duration
        threading.Thread(target=self.unlock_user_account, args=(username, unlock_time)).start()

    def unlock_user_account(self, username, unlock_time):
        time.sleep(self.lock_duration.total_seconds())
        self.locked_users.remove(username)
        messagebox.showinfo("Account Unlocked", f"User account '{username}' has been unlocked.")

    def alert_administrator(self, username):
        # Display alert message with sound
        playsound(r"C:\Users\dell\Downloads\Alert_sound.wav")
        messagebox.showwarning("Suspicious Activity Detected", f"Suspicious activity detected for user: {username}")

    def perform_auto_response(self, username):
        if self.failed_login_attempts >= self.alert_threshold:
            # Send alert to administrator
            self.alert_administrator(username)
            report_filename = self.generate_report()  # Generate report on failed login attempts
            self.lock_user_account(username)
            return report_filename

# Define a class for the login GUI
class LoginGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Login Simulation")
        self.root.geometry("600x300")

        self.user_simulator = UserBehaviorSimulator()
        self.logged_in = False
        self.failed_attempts = 0  # Track the number of failed attempts

        # Create user panel
        self.create_user_panel()

    def create_user_panel(self):
        # User panel
        user_panel = tk.Frame(self.root)
        user_panel.pack(side="left", padx=10, pady=10)

        # User login interface components
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

    def login(self):
        username = self.entry_username.get()
        password = self.entry_password.get()

        credentials = read_credentials(r"C:\Users\dell\Downloads\passwords.txt")

        if credentials and username in credentials and credentials[username] == password:
            self.user_simulator.simulate_login()
            messagebox.showinfo("Login Successful", "Welcome!")
            self.user_simulator.reset_login_attempts()
            self.entry_username.delete(0, tk.END)
            self.entry_password.delete(0, tk.END)
            self.logged_in = True  # Set logged_in flag to True
        else:
            self.user_simulator.simulate_failed_login()
            messagebox.showerror("Login Failed", "Incorrect Username or Password!")
            self.user_simulator.record_credentials(username, password)
            self.failed_attempts += 1
            if self.failed_attempts == 3:
                self.disable_login_button()
                messagebox.showinfo("Account Locked", "You have reached the maximum number of login attempts.")
                report_filename = self.user_simulator.perform_auto_response(username)
                if report_filename:
                    self.open_admin_panel(report_filename)

    def disable_login_button(self):
        self.button_login.config(state=tk.DISABLED)

    def open_admin_panel(self, report_filename):
        # Open administrator panel with options to generate report and view graph
        admin_panel = tk.Toplevel(self.root)
        admin_panel.title("Administrator Panel")

        label_alert = tk.Label(admin_panel, text="Suspicious Activity Detected!")
        label_alert.pack()

        button_view_report = tk.Button(admin_panel, text="Generate Report", command=lambda: self.display_report(report_filename))
        button_view_report.pack(pady=5)

        button_view_graph = tk.Button(admin_panel, text="View Graph", command=self.display_graph)
        button_view_graph.pack(pady=5)

    def display_report(self, report_filename):
        messagebox.showinfo("Report Generated", f"Report saved as {report_filename}")

    def display_graph(self):
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

# Function to read credentials from a file
def read_credentials(file_path):
    credentials = {}
    try:
        with open(file_path, "r") as file:
            for line in file:
                line = line.strip()  # Remove leading/trailing whitespace
                if line:  # Check if the line is not empty
                    parts = line.split(':')
                    if len(parts) == 2:  # Ensure there are exactly two parts (username and password)
                        username, password = parts
                        credentials[username] = password
                    else:
                        print(f"Ignore malformed line: {line}")
    except FileNotFoundError:
        print("Password file not found.")
    return credentials

# Main function to initialize the application
def main():
    root = tk.Tk()
    app = LoginGUI(root)
    root.mainloop()

# Entry point of the application
if __name__ == "__main__":
    main()
    
