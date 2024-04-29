import tkinter as tk
from tkinter import messagebox,simpledialog
from datetime import datetime
import threading
import time
import requests
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import socket
import matplotlib.pyplot as plt
from email.mime.base import MIMEBase
from email import encoders
import random
import string

# Define a class to manage user behavior simulation
class UserBehaviorSimulator:
    def __init__(self):
        self.login_attempts = 0
        self.failed_login_attempts = 0
        self.used_usernames = set()
        self.used_passwords = set()
        self.incidents = []

        # Data for visualization
        self.login_timestamps = []
        self.failed_login_timestamps = []

    def simulate_login(self):
        self.login_attempts += 1
        self.login_timestamps.append(datetime.now())

    def simulate_failed_login(self, ip_address):
        self.failed_login_attempts += 1
        self.failed_login_timestamps.append(datetime.now())
        self.add_incident(datetime.now(), ip_address, "Unknown", "Failed Login", response="Incorrect username or password")

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
            report_file.write("\nIncidents:\n")
            for incident in self.incidents:
                report_file.write(f"- {incident}\n")

        # Create the message body for the email
        subject = "Incident Report and Account Lock Notification"
        message = "Please find the attached incident report. The user account has been locked due to suspicious activity."

        # Attach the incident report to the email
        attachment_filename = report_filename

        # Send the email with the incident report attached
        self.send_email_with_attachment(subject, message, attachment_filename)
        messagebox.showinfo("Report Generated", f"Report saved as {report_filename} and sent via email.")

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
        plt.show()

    def add_incident(self, timestamp, ip_address, username, action, affected_user=None, response=None):
        ip_address_str = f"IPv4: {ip_address[0]}, IPv6: {ip_address[1]}"
        incident_details = f"{timestamp} - IP Address: {ip_address_str}, Username: {username}, Action: {action}"
        if affected_user:
            incident_details += f", Affected User: {affected_user}"
        if response:
            incident_details += f", Response: {response}"
        self.incidents.append(incident_details)

    def lock_user_account(self, username):
        # Implement logic to lock the user account
        pass

    def alert_administrator(self, message):
        # Implement logic to send alerts to administrators
        pass

    def perform_auto_response(self, username):
        # Simulate automated response actions based on predefined rules
        self.lock_user_account(username)  # Lock the user account
        self.add_incident(datetime.now(), ("IPv4 Address", "IPv6 Address"), username, "Account Locked", affected_user=username, response="Automated response: User account locked")

        # Send email notification
        subject = "Account Locked: Suspicious Activity Detected"
        message = f"The user account '{username}' has been locked due to suspicious activity."
        self.send_email(subject, message)

        # Integrate with external tools (example: send alert via HTTP POST request)
        alert_data = {
            "timestamp": str(datetime.now()),
            "username": username,
            "action": "Account Locked",
            "message": "Automated response: User account locked due to suspicious activity"
        }
        response = requests.post("https://example.com/alert", json=alert_data)
        if response.status_code == 200:
            print("Alert sent successfully")
        else:
            print("Failed to send alert")

    def send_email(self, subject, message):
        sender_email = "trackersincident@gmail.com"
        receiver_email = "laganverma010@gmail.com"
        password = "mdtp hujj cvqq wztw"

        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = receiver_email
        msg['Subject'] = subject
        msg.attach(MIMEText(message, 'plain'))

        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login(sender_email, password)
            text = msg.as_string()
            server.sendmail(sender_email, receiver_email, text)

    def send_email_with_attachment(self, subject, message, attachment_filename):
        sender_email = "trackersincident@gmail.com"
        receiver_email = "laganverma010@gmail.com"
        password = "mdtp hujj cvqq wztw"

        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = receiver_email
        msg['Subject'] = subject
        msg.attach(MIMEText(message, 'plain'))

        # Attach the file
        with open(attachment_filename, "rb") as attachment:
            part = MIMEBase("application", "octet-stream")
            part.set_payload(attachment.read())
        encoders.encode_base64(part)
        part.add_header(
            "Content-Disposition",
            f"attachment; filename= {attachment_filename}",
        )
        msg.attach(part)

        # Send the email
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login(sender_email, password)
            text = msg.as_string()
            server.sendmail(sender_email, receiver_email, text)

# Define a class for the login GUI
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


class LoginGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Login Simulation")
        self.root.geometry("400x400")  # Larger window size

        self.user_simulator = UserBehaviorSimulator()
        self.logged_in = False

        self.label_login_attempts = tk.Label(root, text="Login Attempts: 0")
        self.label_login_attempts.pack()
        self.label_failed_attempts = tk.Label(root, text="Failed Login Attempts: 0")
        self.label_failed_attempts.pack()

        self.label_username = tk.Label(root, text="Username:")
        self.label_username.pack()
        self.entry_username = tk.Entry(root)
        self.entry_username.pack()

        self.label_password = tk.Label(root, text="Password:")
        self.label_password.pack()
        self.entry_password = tk.Entry(root, show="*")
        self.entry_password.pack()

        self.label_captcha = tk.Label(root, text="Captcha:")
        self.label_captcha.pack()
        self.entry_captcha = tk.Entry(root)
        self.entry_captcha.pack()

        self.captcha_str = ""
        self.reset_captcha()

        self.button_login = tk.Button(root, text="Login", command=self.login)
        self.button_login.pack()

        self.monitor_thread = threading.Thread(target=self.monitor_login_activity)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()

        # Add a menu bar
        self.menu_bar = tk.Menu(root)
        self.root.config(menu=self.menu_bar)

        # Add a File menu with options to generate report and exit
        self.file_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.menu_bar.add_cascade(label="File", menu=self.file_menu)
        self.file_menu.add_command(label="Generate Report", command=self.generate_report)
        self.file_menu.add_command(label="Exit", command=root.quit)

        # Add a Help menu with an About option
        self.help_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.menu_bar.add_cascade(label="Help", menu=self.help_menu)
        self.help_menu.add_command(label="About", command=self.show_about)

        # Add a View menu with options to view incidents and visualization
        self.view_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.menu_bar.add_cascade(label="View", menu=self.view_menu)
        self.view_menu.add_command(label="View Incidents", command=self.view_incidents)
        self.view_menu.add_command(label="View Visualization", command=self.view_visualization)

        # Add a Send menu with an option to send an alert
        self.send_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.menu_bar.add_cascade(label="Send", menu=self.send_menu)
        self.send_menu.add_command(label="Send Alert", command=self.send_alert)

        # Add a Window menu with options to open a new window and generate random number
        self.window_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.menu_bar.add_cascade(label="Window", menu=self.window_menu)
        self.window_menu.add_command(label="Open Window", command=self.open_window)
        self.window_menu.add_command(label="Generate Random Number", command=self.generate_random_number)
        self.window_menu.add_command(label="Change Label Text", command=self.change_label_text)

        self.new_window = None
        self.label_in_new_window = None

    def reset_captcha(self):
        self.captcha_str = self.generate_captcha()
        self.label_captcha.config(text=self.captcha_str)

    def generate_captcha(self):
        captcha_length = 6
        captcha_characters = string.ascii_letters + string.digits + "/-"
        return ''.join(random.choice(captcha_characters) for i in range(captcha_length))

    # Function to handle login
    def login(self):
        username = self.entry_username.get()
        password = self.entry_password.get()
        captcha = self.entry_captcha.get()

        credentials = read_credentials("passwords.txt")

        if captcha != self.captcha_str:
            messagebox.showerror("Incorrect Captcha", "Please enter the correct captcha.")
            self.reset_captcha()
            return

        if credentials and username in credentials and credentials[username] == password:
            self.user_simulator.simulate_login()
            messagebox.showinfo("Login Successful", "Welcome!")
            self.user_simulator.reset_login_attempts()
            self.entry_username.delete(0, tk.END)
            self.entry_password.delete(0, tk.END)
            self.logged_in = True  # Set logged_in flag to True
        else:
            ip_address = (socket.gethostbyname(socket.gethostname()), socket.getaddrinfo(socket.gethostname(), None)[0][4][0])
            self.user_simulator.simulate_failed_login(ip_address)
            messagebox.showerror("Login Failed", "Incorrect Username or Password!")
            self.user_simulator.record_credentials(username, password)
            if self.user_simulator.failed_login_attempts == 3:
                self.user_simulator.perform_auto_response(username)
                self.user_simulator.generate_report()  # Generate report on failed login attempts
                messagebox.showwarning("No More Attempts", "You have reached the maximum number of login attempts.")
                self.button_login.config(state=tk.DISABLED)

    # Function to monitor login activity
    def monitor_login_activity(self):
        while True:
            self.label_login_attempts.config(text=f"Login Attempts: {self.user_simulator.login_attempts}")
            self.label_failed_attempts.config(text=f"Failed Login Attempts: {self.user_simulator.failed_login_attempts}")
            time.sleep(1)

    # Function to generate and show the report
    def generate_report(self):
        self.user_simulator.generate_report()

    # Function to show the About dialog
    def show_about(self):
        messagebox.showinfo("About", "This is a login simulation application.")

    # Function to view incidents
    def view_incidents(self):
        incidents_window=tk.Toplevel(self.root)
        incidents_window.title("Incidents")
        incidents_window.geometry("400x300")

        scrollbar=tk.Scrollbar(incidents_window)
        scrollbar.pack(side=tk.RIGHT,fill=tk.Y)

        incidents_listbox=tk.Listbox(incidents_window,yscrollcommand=scrollbar.set)
        for incident in self.user_simulator.incidents:
            incidents_listbox.insert(tk.END,incident)
        incidents_listbox.pack(side=tk.LEFT,fill=tk.BOTH,expand=True)  # Expand and fill the entire window

        scrollbar.config(command=incidents_listbox.yview)

    # Function to send an alert
    def send_alert(self):
        subject="Alert: Suspicious Activity Detected"
        message="Suspicious activity has been detected in the system."
        self.user_simulator.send_email(subject,message)
        messagebox.showinfo("Alert Sent","Alert has been sent successfully.")

    # Function to view the login activity visualization
    def view_visualization(self):
        self.user_simulator.generate_visualization()

    # Function to open a new window
    def open_window(self):
        self.new_window = tk.Toplevel(self.root)
        self.new_window.title("New Window")
        self.new_window.geometry("200x100")

        self.label_in_new_window = tk.Label(self.new_window, text="New Window")
        self.label_in_new_window.pack()

    # Function to generate and display a random number in the new window
    def generate_random_number(self):
        if self.new_window and self.label_in_new_window:
            random_number = random.randint(1, 100)
            self.label_in_new_window.config(text=f"Random Number: {random_number}")

    # Function to change the label text in the new window
    def change_label_text(self):
        if self.new_window and self.label_in_new_window:
            new_text = simpledialog.askstring("Change Label Text", "Enter new text:")
            if new_text:
                self.label_in_new_window.config(text=new_text)

# Main function to initialize the application
def main():
    root = tk.Tk()
    app = LoginGUI(root)
    root.mainloop()

# Entry point of the application
if __name__ == "__main__":
    main()
