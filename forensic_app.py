import os
import subprocess
import hashlib
import tkinter as tk
from tkinter import messagebox, filedialog
from datetime import datetime

# ===============================
# Utility Functions
# ===============================

def run_adb_command(command):
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        return result.stdout
    except Exception as e:
        return str(e)

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

def save_output(case_folder, filename, data):
    file_path = os.path.join(case_folder, filename)
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(data)
    hash_value = generate_hash(file_path)
    with open(file_path + ".hash.txt", "w") as hf:
        hf.write("SHA256: " + hash_value)
    return file_path

# ===============================
# Extraction Functions
# ===============================

def check_device():
    output = run_adb_command("adb devices")
    text_area.delete(1.0, tk.END)
    text_area.insert(tk.END, output)

def extract_sms():
    output = run_adb_command("adb shell content query --uri content://sms")
    processed = process_sms(output)
    path = save_output(case_folder, "sms_output.txt", processed)
    messagebox.showinfo("Done", f"SMS saved at:\n{path}")

def process_sms(raw):
    lines = raw.split("Row:")
    formatted = ""
    for line in lines:
        if "date=" in line:
            parts = line.split(",")
            entry = ""
            for p in parts:
                if "date=" in p:
                    ts = p.split("=")[1]
                    entry += "Date: " + convert_timestamp(ts) + "\n"
                elif "address=" in p:
                    entry += "From: " + p.split("=")[1] + "\n"
                elif "body=" in p:
                    entry += "Message: " + p.split("body=")[1] + "\n"
            formatted += entry + "\n-------------------\n"
    return formatted

def extract_calls():
    output = run_adb_command("adb shell content query --uri content://call_log/calls")
    path = save_output(case_folder, "call_logs.txt", output)
    messagebox.showinfo("Done", f"Call logs saved at:\n{path}")

def extract_apps():
    output = run_adb_command("adb shell pm list packages -f")
    path = save_output(case_folder, "installed_apps.txt", output)
    messagebox.showinfo("Done", f"Apps list saved at:\n{path}")

def extract_notifications():
    output = run_adb_command("adb shell dumpsys notification")
    path = save_output(case_folder, "notifications.txt", output)
    messagebox.showinfo("Done", f"Notifications saved at:\n{path}")

def extract_whatsapp():
    output = run_adb_command("adb pull /sdcard/Android/media/com.whatsapp/ " + case_folder)
    messagebox.showinfo("Done", "WhatsApp media pulled to case folder.")

def extract_device_info():
    output = run_adb_command("adb shell getprop")
    path = save_output(case_folder, "device_info.txt", output)
    messagebox.showinfo("Done", f"Device info saved at:\n{path}")

# ===============================
# GUI Setup
# ===============================

root = tk.Tk()
root.title("Android Forensic Tool")
root.geometry("800x600")

case_folder = filedialog.askdirectory(title="Select Case Folder")

label = tk.Label(root, text="Android Forensic Tool - Logical Acquisition", font=("Arial", 14))
label.pack(pady=10)

btn_frame = tk.Frame(root)
btn_frame.pack()

tk.Button(btn_frame, text="Check Device", width=20, command=check_device).grid(row=0, column=0, padx=5, pady=5)
tk.Button(btn_frame, text="Extract SMS", width=20, command=extract_sms).grid(row=0, column=1, padx=5, pady=5)
tk.Button(btn_frame, text="Extract Call Logs", width=20, command=extract_calls).grid(row=1, column=0, padx=5, pady=5)
tk.Button(btn_frame, text="Extract Installed Apps", width=20, command=extract_apps).grid(row=1, column=1, padx=5, pady=5)
tk.Button(btn_frame, text="Extract Notifications", width=20, command=extract_notifications).grid(row=2, column=0, padx=5, pady=5)
tk.Button(btn_frame, text="Extract WhatsApp Media", width=20, command=extract_whatsapp).grid(row=2, column=1, padx=5, pady=5)
tk.Button(btn_frame, text="Extract Device Info", width=20, command=extract_device_info).grid(row=3, column=0, padx=5, pady=5)

text_area = tk.Text(root, height=15)
text_area.pack(fill="both", expand=True)

root.mainloop()
