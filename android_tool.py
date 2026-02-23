import os
import subprocess
import hashlib
import threading
import tkinter as tk
from tkinter import messagebox, filedialog
from datetime import datetime
import re

# ===============================
# GLOBAL VARIABLES
# ===============================
whatsapp_process = None
stop_flag = False
case_folder = ""

# ===============================
# UTILITY FUNCTIONS
# ===============================

def run_adb_command(command):
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout

def convert_timestamp(ms):
    try:
        return datetime.fromtimestamp(int(ms)/1000).strftime('%Y-%m-%d %H:%M:%S')
    except:
        return ms

def generate_hash(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

def save_output(filename, data):
    file_path = os.path.join(case_folder, filename)
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(data)

    hash_value = generate_hash(file_path)
    with open(file_path + ".hash.txt", "w") as hf:
        hf.write("SHA256: " + hash_value)

    return file_path

# ===============================
# SMS PARSER (Human Readable)
# ===============================

def parse_sms(raw):
    rows = raw.split("Row:")
    formatted = ""

    for row in rows:
        if "date=" in row:
            address = re.search(r'address=(.*?),', row)
            body = re.search(r'body=(.*)', row)
            date = re.search(r'date=(\d+)', row)
            type_ = re.search(r'type=(\d+)', row)

            direction = "Received"
            if type_ and type_.group(1) == "2":
                direction = "Sent"

            formatted += "---------------------------------\n"
            formatted += f"Date      : {convert_timestamp(date.group(1))}\n"
            formatted += f"From/To   : {address.group(1)}\n"
            formatted += f"Direction : {direction}\n"
            formatted += f"Message   : {body.group(1)}\n\n"

    return formatted

# ===============================
# CALL LOG PARSER (Human Readable)
# ===============================

def parse_calls(raw):
    rows = raw.split("Row:")
    formatted = ""

    for row in rows:
        if "date=" in row:
            number = re.search(r'number=(.*?),', row)
            duration = re.search(r'duration=(\d+)', row)
            date = re.search(r'date=(\d+)', row)
            type_ = re.search(r'type=(\d+)', row)

            call_type = {
                "1": "Incoming",
                "2": "Outgoing",
                "3": "Missed",
                "4": "Voicemail",
                "5": "Rejected"
            }.get(type_.group(1), "Unknown")

            formatted += "---------------------------------\n"
            formatted += f"Date     : {convert_timestamp(date.group(1))}\n"
            formatted += f"Number   : {number.group(1)}\n"
            formatted += f"Type     : {call_type}\n"
            formatted += f"Duration : {duration.group(1)} seconds\n\n"

    return formatted

# ===============================
# EXTRACTION FUNCTIONS
# ===============================

def check_device():
    output = run_adb_command("adb devices")
    text_area.delete(1.0, tk.END)
    text_area.insert(tk.END, output)

def extract_sms():
    raw = run_adb_command("adb shell content query --uri content://sms")
    readable = parse_sms(raw)
    path = save_output("sms_readable.txt", readable)
    messagebox.showinfo("Done", f"SMS saved:\n{path}")

def extract_calls():
    raw = run_adb_command("adb shell content query --uri content://call_log/calls")
    readable = parse_calls(raw)
    path = save_output("call_logs_readable.txt", readable)
    messagebox.showinfo("Done", f"Call logs saved:\n{path}")

def extract_apps():
    output = run_adb_command("adb shell pm list packages -f")
    path = save_output("installed_apps.txt", output)
    messagebox.showinfo("Done", f"Installed apps saved:\n{path}")

def extract_notifications():
    output = run_adb_command("adb shell dumpsys notification")
    path = save_output("notifications.txt", output)
    messagebox.showinfo("Done", f"Notifications saved:\n{path}")

def extract_device_info():
    output = run_adb_command("adb shell getprop")
    path = save_output("device_info.txt", output)
    messagebox.showinfo("Done", f"Device info saved:\n{path}")

# ===============================
# WHATSAPP EXTRACTION (THREAD + STOP)
# ===============================

def extract_whatsapp():
    global whatsapp_process, stop_flag
    stop_flag = False
    status_label.config(text="Status: Extracting WhatsApp Media...")

    def run_pull():
        global whatsapp_process
        command = f'adb pull /sdcard/Android/media/com.whatsapp/ "{case_folder}"'
        whatsapp_process = subprocess.Popen(command, shell=True)

        while whatsapp_process.poll() is None:
            if stop_flag:
                whatsapp_process.terminate()
                status_label.config(text="Status: Extraction Stopped")
                return

        status_label.config(text="Status: WhatsApp Extraction Completed")
        messagebox.showinfo("Done", "WhatsApp extraction completed.")

    threading.Thread(target=run_pull).start()

def stop_whatsapp_extraction():
    global stop_flag
    stop_flag = True

# ===============================
# GUI SETUP
# ===============================

root = tk.Tk()
root.title("Android Forensic Tool - Logical Acquisition")
root.geometry("950x700")

case_folder = filedialog.askdirectory(title="Select Case Folder")
if not case_folder:
    messagebox.showerror("Error", "No case folder selected.")
    root.destroy()

title_label = tk.Label(root, text="Android Forensic Tool", font=("Arial", 16, "bold"))
title_label.pack(pady=10)

btn_frame = tk.Frame(root)
btn_frame.pack(pady=10)

tk.Button(btn_frame, text="Check Device", width=28, command=check_device).grid(row=0, column=0, padx=5, pady=5)
tk.Button(btn_frame, text="Extract SMS (Readable)", width=28, command=extract_sms).grid(row=0, column=1, padx=5, pady=5)

tk.Button(btn_frame, text="Extract Call Logs (Readable)", width=28, command=extract_calls).grid(row=1, column=0, padx=5, pady=5)
tk.Button(btn_frame, text="Extract Installed Apps", width=28, command=extract_apps).grid(row=1, column=1, padx=5, pady=5)

tk.Button(btn_frame, text="Extract Notifications", width=28, command=extract_notifications).grid(row=2, column=0, padx=5, pady=5)
tk.Button(btn_frame, text="Extract Device Info", width=28, command=extract_device_info).grid(row=2, column=1, padx=5, pady=5)

tk.Button(btn_frame, text="Extract WhatsApp Media", width=28, command=extract_whatsapp, bg="green", fg="white").grid(row=3, column=0, padx=5, pady=5)
tk.Button(btn_frame, text="STOP WhatsApp Extraction", width=28, command=stop_whatsapp_extraction, bg="red", fg="white").grid(row=3, column=1, padx=5, pady=5)

status_label = tk.Label(root, text="Status: Idle", font=("Arial", 12))
status_label.pack(pady=5)

text_area = tk.Text(root, height=20)
text_area.pack(fill="both", expand=True, padx=10, pady=10)

root.mainloop()
