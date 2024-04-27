from datetime import datetime
import matplotlib.pyplot as plt
from tkinter import messagebox
from playsound import playsound

class UserBehaviorSimulator:
    def __init__(self):
        self.login_attempts = 0
        self.failed_login_attempts = 0
        self.used_usernames = set()
        self.used_passwords = set()
        self.incidents = []
        self.login_timestamps = []
        self.failed_login_timestamps = []
        self.alert_threshold = 3

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
        self.generate_visualization()
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
        messagebox.showinfo("Report Generated", f"Report saved as {report_filename}")

    def generate_visualization(self):
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
        plt.savefig(visualization_filename)  
        plt.close()

    def add_incident(self, timestamp, ip_address, username, action, affected_user=None, response=None):
        incident_details = f"{timestamp} - IP: {ip_address}, Username: {username}, Action: {action}"
        if affected_user:
            incident_details += f", Affected User: {affected_user}"
        if response:
            incident_details += f", Response: {response}"
        self.incidents.append(incident_details)

    def lock_user_account(self, username):
        pass

    def alert_administrator(self, message):
        messagebox.showwarning("Alert", message)
        playsound("alert_sound.wav")

    def perform_auto_response(self, username):
        if self.failed_login_attempts >= self.alert_threshold:
            alert_message = f"Suspicious login activity detected for user: {username}"
            self.alert_administrator(alert_message)
            self.generate_report()
