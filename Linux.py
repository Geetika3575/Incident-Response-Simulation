import tkinter as tk
from tkinter import messagebox
import threading
import time
import subprocess

# Define a class for the login GUI
class LoginGUI:
    def _init_(self, root):
        self.root = root
        self.root.title("Login Simulation")
        self.root.geometry("300x250")

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

        self.button_login = tk.Button(root, text="Login", command=self.login)
        self.button_login.pack()

        self.monitor_thread = threading.Thread(target=self.monitor_login_activity)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()

    # Function to handle login
    def login(self):
        username = self.entry_username.get()
        password = self.entry_password.get()

        # Simulate authentication
        if username == "admin" and password == "password":
            messagebox.showinfo("Login Successful", "Welcome!")

            # Ask incident response questions
            if self.ask_incident_response_questions():
                # Prompt the user to run Nmap
                if messagebox.askyesno("Run Nmap", "Do you want to run Nmap?"):
                    self.run_nmap_scan()
        else:
            messagebox.showerror("Login Failed", "Incorrect Username or Password!")

    # Function to monitor login activity
    def monitor_login_activity(self):
        while True:
            # Simulate monitoring
            self.label_login_attempts.config(text="Login Attempts: <simulate_value>")
            self.label_failed_attempts.config(text="Failed Login Attempts: <simulate_value>")
            time.sleep(1)

    # Function to ask incident response questions
    def ask_incident_response_questions(self):
        # Define questions and answers
        questions = [
            "What is the first step in incident response?",
            "What is the purpose of an incident response plan?",
            "Why is it important to document incident response actions?"
        ]
        answers = [
            ["Identify", "Prepare"],
            ["To provide a structured approach for responding to security incidents.", "To gather evidence for legal proceedings."],
            ["To facilitate analysis, improve incident response processes, and aid in legal and compliance requirements.", "To create a report for management."]
        ]
        correct_answers = []

        # Ask incident response questions
        for i, question in enumerate(questions):
            top = tk.Toplevel(self.root)
            top.title("Question " + str(i+1))
            top.geometry("300x200")

            label = tk.Label(top, text=question)
            label.pack()

            var = tk.IntVar()
            for j, choice in enumerate(answers[i]):
                button = tk.Radiobutton(top, text=choice, value=j, variable=var)
                button.pack()

            button_submit = tk.Button(top, text="Submit", command=lambda i=i, top=top, var=var: self.check_answer(i, var.get(), top, correct_answers))
            button_submit.pack()

            top.grab_set()
            top.wait_window()

            if len(correct_answers) == len(questions):
                break

        # Check if all answers are correct
        if len(correct_answers) == len(questions):
            messagebox.showinfo("Correct Answers", "All answers are correct.")
            return True
        else:
            messagebox.showerror("Incorrect Answers", "One or more answers are incorrect.")
            return False

    # Function to check the answer for a question
    def check_answer(self, question_index, answer_index, top, correct_answers):
        if answer_index == 0:
            correct_answers.append(question_index)
        top.destroy()

    # Function to run Nmap scan
    def run_nmap_scan(self):
        try:
            # Run Nmap scan
            output = subprocess.check_output(["nmap", "-v", "-A", "localhost"])
            messagebox.showinfo("Nmap Scan Result", output.decode())
        except Exception as e:
            messagebox.showerror("Nmap Error", str(e))

# Main function to initialize the application
def main():
    root = tk.Tk()
    app = LoginGUI(root)
    root.mainloop()

# Entry point of the application
if _name_ == "_main_":
    main()