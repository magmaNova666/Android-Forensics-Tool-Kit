import os
import subprocess
import hashlib
import threading
import tkinter as tk
from tkinter import messagebox, filedialog, ttk
from datetime import datetime
import re
import time
import requests

# =========================================================
# GLOBAL DATA STRUCTURES
# =========================================================
case_folder = ""
log_file = ""
stop_flag = False

contacts_dict = {}          # number -> name
communication_stats = {}    # number -> interaction count
timeline_data = {}          # timestamp -> [events]

# =========================================================
# CORE UTILITIES
# =========================================================

def log_action(action):
    if log_file:
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(f"[{datetime.now()}] {action}\n")

def run_adb(cmd):
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        log_action(f"CMD Executed: {cmd}")
        return result.stdout
    except Exception as e:
        log_action(f"ADB ERROR: {e}")
        return ""

def check_device():
    output = subprocess.run("adb devices", shell=True, capture_output=True, text=True).stdout
    lines = output.splitlines()
    devices = [l for l in lines[1:] if l.strip() and "device" in l and "unauthorized" not in l]

    if not devices:
        messagebox.showerror("Error", "No authorized Android device connected!\nCheck USB Debugging.")
        return False
    return True

def save_file(filename, data):
    path = os.path.join(case_folder, filename)
    with open(path, "w", encoding="utf-8") as f:
        f.write(data)

    # Cryptographic Hashing for Chain of Custody
    file_bytes = open(path, "rb").read()
    sha = hashlib.sha256(file_bytes).hexdigest()
    with open(path + ".hash.txt", "w") as h:
        h.write(f"SHA256: {sha}\nGenerated: {datetime.now()}")
    return path

def convert_time(ms):
    try:
        return datetime.fromtimestamp(int(ms)/1000).strftime("%Y-%m-%d %H:%M:%S")
    except:
        return str(ms)

def normalize_number(num):
    return re.sub(r'[^\d+]', '', str(num))

# =========================================================
# EXTRACTION MODULES
# =========================================================

def extract_device_metadata():
    if not check_device(): return
    metadata = f"--- DEVICE METADATA REPORT ---\n"
    metadata += f"Model: {run_adb('adb shell getprop ro.product.model').strip()}\n"
    metadata += f"Android Version: {run_adb('adb shell getprop ro.build.version.release').strip()}\n"
    metadata += f"Serial: {run_adb('adb get-serialno').strip()}\n"
    metadata += f"Current Device Time: {run_adb('adb shell date').strip()}\n"
    metadata += f"Acquisition Timestamp: {datetime.now()}\n"
    
    save_file("01_device_metadata.txt", metadata)
    messagebox.showinfo("Success", "Metadata Extracted and Hashed.")

def extract_contacts():
    global contacts_dict
    if not check_device(): return
    raw = run_adb("adb shell content query --uri content://contacts/phones/")
    contacts_dict.clear()
    formatted = "Name | Number\n" + "-"*30 + "\n"

    for row in raw.split("Row:"):
        name = re.search(r'display_name=(.*?),', row)
        number = re.search(r'number=(.*?)(,|$)', row)
        if name and number:
            c_name = name.group(1).strip()
            c_num = normalize_number(number.group(1))
            contacts_dict[c_num] = c_name
            formatted += f"{c_name} | {c_num}\n"

    save_file("02_contacts.txt", formatted)
    messagebox.showinfo("Success", f"Extracted {len(contacts_dict)} contacts.")

def extract_comms():
    """Extracts SMS and Call Logs and populates analytics."""
    if not check_device(): return
    global communication_stats, timeline_data
    communication_stats.clear()
    timeline_data.clear()

    # --- SMS EXTRACTION ---
    sms_raw = run_adb("adb shell content query --uri content://sms")
    sms_out = "Timestamp | Name | Number | Direction | Content\n"
    for row in sms_raw.split("Row:"):
        addr = re.search(r'address=(.*?),', row)
        body = re.search(r'body=(.*?),', row) # Simplified regex for body
        date = re.search(r'date=(\d+)', row)
        type_ = re.search(r'type=(\d+)', row)

        if addr and date and type_:
            num = normalize_number(addr.group(1))
            name = contacts_dict.get(num, "Unknown")
            dir_str = "Received" if type_.group(1) == "1" else "Sent"
            time_str = convert_time(date.group(1))
            
            communication_stats[num] = communication_stats.get(num, 0) + 1
            timeline_data.setdefault(time_str, []).append(f"SMS {dir_str}: {name} ({num})")
            sms_out += f"{time_str} | {name} | {num} | {dir_str} | {body.group(1) if body else '[No Body]'}\n"

    # --- CALL LOG EXTRACTION ---
    call_raw = run_adb("adb shell content query --uri content://call_log/calls")
    call_out = "Timestamp | Name | Number | Type | Duration(s)\n"
    for row in call_raw.split("Row:"):
        num_match = re.search(r'number=(.*?),', row)
        dur_match = re.search(r'duration=(\d+)', row)
        date_match = re.search(r'date=(\d+)', row)
        type_match = re.search(r'type=(\d+)', row)

        if num_match and date_match:
            num = normalize_number(num_match.group(1))
            name = contacts_dict.get(num, "Unknown")
            c_type = {"1":"Incoming","2":"Outgoing","3":"Missed"}.get(type_match.group(1),"Unknown")
            time_str = convert_time(date_match.group(1))
            dur = dur_match.group(1) if dur_match else "0"

            communication_stats[num] = communication_stats.get(num, 0) + 1
            timeline_data.setdefault(time_str, []).append(f"{c_type} Call: {name} ({num}) - {dur}s")
            call_out += f"{time_str} | {name} | {num} | {c_type} | {dur}\n"

    save_file("03_sms_messages.txt", sms_out)
    save_file("04_call_logs.txt", call_out)
    generate_reports()
    messagebox.showinfo("Success", "SMS and Call Logs extracted and analyzed.")

# =========================================================
# ANALYTICS & AI
# =========================================================

def generate_reports():
    # Top 5 Contacts
    top = sorted(communication_stats.items(), key=lambda x: x[1], reverse=True)[:5]
    report = "--- TOP 5 MOST CONTACTED ---\n"
    for i, (num, count) in enumerate(top, 1):
        name = contacts_dict.get(num, "Unknown")
        report += f"{i}. {name} ({num}) - {count} interactions\n"
    save_file("05_top_contacts.txt", report)

    # Master Timeline
    t_report = "--- MASTER COMMUNICATION TIMELINE ---\n"
    for t in sorted(timeline_data.keys()):
        for event in timeline_data[t]:
            t_report += f"[{t}] {event}\n"
    save_file("06_timeline.txt", t_report)

def analyze_with_ai():
    file_path = filedialog.askopenfilename(title="Select Evidence File", filetypes=[("Text Files","*.txt")])
    if not file_path: return

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

    # Risk Calculation Logic
    score = 0
    keywords = ["urgent", "delete", "transfer", "money", "crypto", "bank", "password", "otp", "secret"]
    for word in keywords:
        score += content.lower().count(word) * 5
    
    level = "LOW" if score < 30 else "MEDIUM" if score < 70 else "HIGH"

    prompt = f"Perform a forensic analysis on this data. Highlight suspicious patterns, frequent contacts, and potential risks:\n\n{content[:6000]}"

    try:
        log_action("AI Analysis Requested (Ollama)")
        response = requests.post(
            "http://localhost:11434/api/generate",
            json={"model": "llama3", "prompt": prompt, "stream": False},
            timeout=180
        )
        ai_response = response.json().get("response", "No AI response received.")
        
        final_report = f"RISK SCORE: {score}\nRISK LEVEL: {level}\n\nAI FORENSIC INSIGHTS:\n{ai_response}"
        save_file("09_AI_Forensic_Report.txt", final_report)
        
        # Display Result
        win = tk.Toplevel(root)
        win.title("AI Analysis Result")
        txt = tk.Text(win, wrap="word", padx=10, pady=10)
        txt.pack(expand=True, fill="both")
        txt.insert("1.0", final_report)
    except Exception as e:
        messagebox.showerror("AI Error", f"Ensure Ollama is running on localhost:11434\nError: {e}")

# =========================================================
# MEDIA / WHATSAPP MODULE
# =========================================================

def categorize_whatsapp(path):
    p = path.lower()
    mapping = {
        "images": "Images", "video": "Video", "audio": "Audio", 
        "voice": "Voice_Notes", "documents": "Docs", "databases": "DBs"
    }
    for key, folder in mapping.items():
        if key in p: return folder
    return "Miscellaneous"

def start_whatsapp_extraction():
    if not check_device(): return
    global stop_flag
    stop_flag = False
    
    base_path = os.path.join(case_folder, "Media_Extraction")
    os.makedirs(base_path, exist_ok=True)

    def run():
        files = run_adb('adb shell "find /sdcard/Android/media/com.whatsapp/ -type f"').splitlines()
        total = len(files)
        progress["maximum"] = total
        
        start_t = time.time()
        for i, f_path in enumerate(files):
            if stop_flag: break
            
            cat = categorize_whatsapp(f_path)
            dest_dir = os.path.join(base_path, cat)
            os.makedirs(dest_dir, exist_ok=True)
            
            subprocess.run(["adb", "pull", f_path, dest_dir], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            # Update UI
            progress["value"] = i + 1
            elapsed = time.time() - start_t
            eta = int((elapsed/(i+1)) * (total-(i+1))) if i > 0 else 0
            status_label.config(text=f"Copying: {i+1}/{total} | ETA: {eta//60}m {eta%60}s")
            root.update_idletasks()

        messagebox.showinfo("Done", "Media Extraction Finished.")

    threading.Thread(target=run, daemon=True).start()

# =========================================================
# GUI INITIALIZATION
# =========================================================

root = tk.Tk()
root.title("Forensic-AI Unified Suite")
root.geometry("600x750")

# Initial setup
case_folder = filedialog.askdirectory(title="Create/Select Case Directory")
if not case_folder:
    root.destroy()
    exit()

log_file = os.path.join(case_folder, "case_activity.log")
log_action("Case Initialized")

# UI Layout
header = tk.Label(root, text="Android Forensic & AI Analysis", font=("Arial", 16, "bold"), pady=20)
header.pack()

btn_frame = tk.Frame(root)
btn_frame.pack(pady=10)

actions = [
    ("1. Extract Device Metadata", extract_device_metadata),
    ("2. Extract Contact List", extract_contacts),
    ("3. Extract SMS & Call History", extract_comms),
    ("4. List Installed Packages", lambda: save_file("07_apps.txt", run_adb("adb shell pm list packages -f"))),
    ("5. Dump System Notifications", lambda: save_file("08_notifications.txt", run_adb("adb shell dumpsys notification"))),
    ("6. Begin Media Extraction (WhatsApp)", start_whatsapp_extraction),
    ("7. STOP Extraction", lambda: globals().update(stop_flag=True)),
    ("8. Run AI Forensic Analysis", analyze_with_ai),
]

for text, func in actions:
    tk.Button(btn_frame, text=text, width=45, command=func, pady=5).pack(pady=3)

progress = ttk.Progressbar(root, length=400, mode='determinate')
progress.pack(pady=20)

status_label = tk.Label(root, text="Ready", fg="blue")
status_label.pack()

root.mainloop()
