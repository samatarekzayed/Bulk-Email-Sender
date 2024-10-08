import os
import base64
import google.auth
import google.auth.transport.requests
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import csv
import tkinter as tk
from tkinter import ttk, messagebox
import re

SCOPES = ['https://www.googleapis.com/auth/gmail.send']

class GmailAPI:
    def __init__(self, credentials_file='C:/Users/dell/Downloads/client_secret_samatarekanwarzayed@gmail.com.json', token_file='token.json'):
        self.credentials_file = credentials_file
        self.token_file = token_file
        self.creds = None

    def authenticate(self):
        if os.path.exists(self.token_file):
            self.creds = Credentials.from_authorized_user_file(self.token_file, SCOPES)
        if not self.creds or not self.creds.valid:
            if self.creds and self.creds.expired and self.creds.refresh_token:
                self.creds.refresh(google.auth.transport.requests.Request())
            else:
                flow = InstalledAppFlow.from_client_secrets_file(self.credentials_file, SCOPES)
                self.creds = flow.run_local_server(port=0)
            with open(self.token_file, 'w') as token:
                token.write(self.creds.to_json())

    def send_email(self, to_email, subject, message_text):
        try:
            service = build('gmail', 'v1', credentials=self.creds)
            message = MIMEMultipart()
            message['to'] = to_email
            message['from'] = 'samatarekanwarzayed@gmail.com'
            message['subject'] = subject
            message.attach(MIMEText(message_text, 'html'))

            raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
            message = {'raw': raw_message}

            service.users().messages().send(userId="me", body=message).execute()
            return True
        except HttpError as error:
            print(f'Failed to send email to {to_email}: {error}')
            return False

    def remove_email_from_csv(self, email, csv_file_path):
        emails = []
        with open(csv_file_path, 'r') as csv_file:
            csv_reader = csv.reader(csv_file)
            emails = [row for row in csv_reader if row and len(row) > 0 and row[0].strip() != email]

        with open(csv_file_path, 'w', newline='') as csv_file:
            csv_writer = csv.writer(csv_file)
            csv_writer.writerows(emails)

class EmailSenderApp:
    def __init__(self, root, gmail_api, email_csv_file, html_csv_file):
        self.root = root
        self.gmail_api = gmail_api
        self.email_csv_file = email_csv_file
        self.html_csv_file = html_csv_file
        self.subject = "Test Subject"
        self.message_text = "This is a test email using Gmail API"
        self.email_list = []
        self.selected_html_content = ""

        self.root.title("Advanced Email Sender")
        self.root.geometry("2000x700")

        style = ttk.Style(self.root)
        style.theme_use('clam')
        style.configure('TButton', font=('Helvetica', 12))
        style.configure('TLabel', font=('Helvetica', 12))
        style.configure('TEntry', font=('Helvetica', 12))
        style.configure("Success.TButton", font=('Helvetica', 12), background="#28a745", foreground="white")
        style.configure("Danger.TButton", font=('Helvetica', 12), background="#dc3545", foreground="white")

        self.main_frame = ttk.Frame(root)
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        self.main_frame.grid_columnconfigure(0, weight=1, uniform="equal")
        self.main_frame.grid_columnconfigure(1, weight=1, uniform="equal")

        self.email_list_frame = ttk.Frame(self.main_frame, borderwidth=2, relief="ridge")
        self.email_list_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

        self.email_input_frame = ttk.Frame(self.main_frame, borderwidth=2, relief="ridge")
        self.email_input_frame.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")

        self.html_list_frame = ttk.Frame(self.main_frame, borderwidth=2, relief="ridge")
        self.html_list_frame.grid(row=1, column=0, padx=10, pady=10, sticky="nsew")

        self.html_input_frame = ttk.Frame(self.main_frame, borderwidth=2, relief="ridge")
        self.html_input_frame.grid(row=1, column=1, padx=10, pady=10, sticky="nsew")

        self.title_label = ttk.Label(self.email_list_frame, text="Email List", font=("Helvetica", 18, "bold"))
        self.title_label.pack(pady=10)

        self.scrollbar = ttk.Scrollbar(self.email_list_frame)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.email_listbox = tk.Listbox(self.email_list_frame, height=10, width=40, yscrollcommand=self.scrollbar.set, font=('Helvetica', 14))
        self.email_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.scrollbar.config(command=self.email_listbox.yview)

        self.send_button = ttk.Button(self.email_list_frame, text="Send All Emails", style="Success.TButton", command=self.send_all_emails)
        self.send_button.pack(pady=10)

        self.clear_button = ttk.Button(self.email_list_frame, text="Clear Emails !!!", style="Danger.TButton", command=self.clear_emails)
        self.clear_button.pack(pady=10)

        self.info_label = ttk.Label(self.email_list_frame, text="", foreground="green")
        self.info_label.pack(pady=5)

        self.status_bar = ttk.Label(root, text="Ready", relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        self.email_input_label = ttk.Label(self.email_input_frame, text="Add Emails (comma-separated or one per line):", font=("Helvetica", 18, "bold"))
        self.email_input_label.pack(pady=10)

        self.email_input_text = tk.Text(self.email_input_frame, height=10, width=40, font=('Helvetica', 14))
        self.email_input_text.pack(pady=5)

        self.add_button = ttk.Button(self.email_input_frame, text="Add Emails", style="Success.TButton", command=self.add_emails)
        self.add_button.pack(pady=10)

        self.load_emails()

        self.html_list_label = ttk.Label(self.html_list_frame, text="HTML Content", font=("Helvetica", 18, "bold"))
        self.html_list_label.pack(pady=10)

        self.html_listbox = tk.Listbox(self.html_list_frame, height=10, width=40, font=('Helvetica', 14))
        self.html_listbox.pack(fill=tk.BOTH, expand=True)

        self.load_html_content()

        self.html_input_label = ttk.Label(self.html_input_frame, text="Add HTML Content (one per line):", font=("Helvetica", 18, "bold"))
        self.html_input_label.pack(pady=10)

        self.html_input_text = tk.Text(self.html_input_frame, height=10, width=40, font=('Helvetica', 14))
        self.html_input_text.pack(pady=5)

        self.add_html_button = ttk.Button(self.html_input_frame, text="Add HTML Content", style="Success.TButton", command=self.add_html_content)
        self.add_html_button.pack(pady=10)

        self.select_html_button = ttk.Button(self.html_input_frame, text="Select HTML Content", style="Success.TButton", command=self.select_html_content)
        self.select_html_button.pack(pady=10)

        style.configure("TFrame", background="#0f172a")
        style.configure("TLabel", background="#0f172a", foreground="white")
        style.configure("TButton", background="#0f172a")

    def clear_emails(self):
        """Clear all emails from the CSV file and the listbox."""
        if messagebox.askyesno("Confirm", "Are you sure you want to clear all emails?"):
            open(self.email_csv_file, 'w').close()
            self.load_emails()
            self.info_label.config(text="All emails have been cleared.", foreground="red")

    def load_emails(self):
        """Load emails from CSV file into the listbox."""
        self.email_listbox.delete(0, tk.END)
        with open(self.email_csv_file, 'r') as csv_file:
            csv_reader = csv.reader(csv_file)
            for row in csv_reader:
                if row and len(row) > 0:
                    self.email_listbox.insert(tk.END, row[0].strip())

    def load_html_content(self):
        """Load HTML content from CSV file into the listbox."""
        self.html_listbox.delete(0, tk.END)
        with open(self.html_csv_file, 'r') as csv_file:
            csv_reader = csv.reader(csv_file)
            for row in csv_reader:
                if row and len(row) > 0:
                    self.html_listbox.insert(tk.END, row[0].strip())

    def add_emails(self):
        """Add new emails to the CSV file from the text widget."""
        new_emails = self.email_input_text.get("1.0", tk.END).strip()
        if not new_emails:
            messagebox.showwarning("Input Error", "Please enter some email addresses.")
            return

        emails = re.split(r'[,; \n]+', new_emails)
        with open(self.email_csv_file, 'a', newline='') as csv_file:
            csv_writer = csv.writer(csv_file)
            for email in emails:
                if email:
                    csv_writer.writerow([email.strip()])

        self.email_input_text.delete("1.0", tk.END)
        self.load_emails()

    def add_html_content(self):
        """Add new HTML content to the CSV file from the text widget."""
        new_html_content = self.html_input_text.get("1.0", tk.END).strip()
        if not new_html_content:
            messagebox.showwarning("Input Error", "Please enter some HTML content.")
            return

        with open(self.html_csv_file, 'a', newline='') as csv_file:
            csv_writer = csv.writer(csv_file)
            csv_writer.writerow([new_html_content])

        self.html_input_text.delete("1.0", tk.END)
        self.load_html_content()

    def select_html_content(self):
        """Get the selected HTML content from the listbox."""
        try:
            selected_index = self.html_listbox.curselection()[0]
            self.selected_html_content = self.html_listbox.get(selected_index)
            self.info_label.config(text=f"Selected HTML content: {selected_index + 1}", foreground="blue")
        except IndexError:
            messagebox.showwarning("Selection Error", "Please select an HTML content from the list.")

    def send_all_emails(self):
        """Send emails to all addresses in the list and provide feedback in the GUI."""
        if not self.email_listbox.size():
            self.info_label.config(text="No emails to send.", foreground="red")
            return

        if not self.selected_html_content:
            messagebox.showwarning("HTML Content Error", "Please select HTML content before sending emails.")
            return

        if not messagebox.askyesno("Confirm", "Are you sure you want to send emails to all listed addresses?"):
            return

        self.progress_bar = ttk.Progressbar(self.email_list_frame, length=200)
        self.progress_bar.pack(pady=10)
        self.progress_bar['maximum'] = self.email_listbox.size()
        self.progress_bar['value'] = 0

        for index in range(self.email_listbox.size()):
            email = self.email_listbox.get(index)
            self.info_label.config(text=f"Sending email to: {email}...", foreground="blue")
            self.root.update_idletasks()

            if self.gmail_api.send_email(email, self.subject, self.selected_html_content):
                self.gmail_api.remove_email_from_csv(email, self.email_csv_file)
                self.info_label.config(text=f"Email sent to {email}", foreground="green")
            else:
                self.info_label.config(text=f"Failed to send to {email}", foreground="red")

            self.progress_bar['value'] += 1
            self.root.update_idletasks()

        self.info_label.config(text="All emails have been processed.", foreground="green")
        self.load_emails()

if __name__ == "__main__":
    gmail_api = GmailAPI()
    gmail_api.authenticate()

    root = tk.Tk()
    app = EmailSenderApp(root, gmail_api, 'emails.csv', 'html_content.csv')
    root.mainloop()
