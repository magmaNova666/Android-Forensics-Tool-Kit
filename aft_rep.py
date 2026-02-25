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

from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.lib import pagesizes

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

def extract_sms_module():
    if not check_device():
        return

    sms_raw = run_adb("adb shell content query --uri content://sms")

    report = "\n========== SMS EXTRACTION REPORT ==========\n"

    for row in sms_raw.split("Row:"):
        addr = re.search(r'address=(.*?),', row)
        body = re.search(r'body=(.*?),', row)
        date = re.search(r'date=(\d+)', row)
        type_ = re.search(r'type=(\d+)', row)

        if addr and date and type_:
            number = normalize_number(addr.group(1))
            name = contacts_dict.get(number, "Unknown Contact")
            direction = "Received" if type_.group(1) == "1" else "Sent"
            timestamp = convert_time(date.group(1))
            message = body.group(1) if body else "[No Content]"

            report += f"""
--------------------------------------------
Date & Time : {timestamp}
Contact     : {name}
Phone No.   : {number}
Direction   : {direction}
Message     : {message}
--------------------------------------------
"""

    save_file("03_SMS_Report.txt", report)
    messagebox.showinfo("Success", "SMS Extraction Completed")

def extract_calllog_module():
    if not check_device():
        return

    call_stats = {}
    call_duration = {}

    call_raw = run_adb("adb shell content query --uri content://call_log/calls")

    report = "\n========== CALL LOG REPORT ==========\n"

    for row in call_raw.split("Row:"):
        num_match = re.search(r'number=(.*?),', row)
        date_match = re.search(r'date=(\d+)', row)
        type_match = re.search(r'type=(\d+)', row)
        dur_match = re.search(r'duration=(\d+)', row)

        if num_match and date_match:

            number = normalize_number(num_match.group(1))
            name = contacts_dict.get(number, "Unknown Contact")
            timestamp = convert_time(date_match.group(1))

            call_type = {
                "1": "Incoming",
                "2": "Outgoing",
                "3": "Missed"
            }.get(type_match.group(1), "Unknown")

            duration = int(dur_match.group(1)) if dur_match else 0

            call_stats[number] = call_stats.get(number, 0) + 1
            call_duration[number] = call_duration.get(number, 0) + duration

            report += f"""
--------------------------------------------
Date & Time : {timestamp}
Contact     : {name}
Phone No.   : {number}
Call Type   : {call_type}
Duration    : {duration} seconds
--------------------------------------------
"""

    save_file("04_Call_Log_Report.txt", report)

    generate_top10_call_duration(call_stats, call_duration)

def get_whatsapp_extraction_summary():

    base_path = os.path.join(case_folder, "Media_Extraction")

    if not os.path.exists(base_path):
        return None

    summary = {}
    total_size = 0

    for category in os.listdir(base_path):
        cat_path = os.path.join(base_path, category)

        if os.path.isdir(cat_path):
            file_count = 0
            size = 0

            for root_dir, _, files in os.walk(cat_path):
                for f in files:
                    file_count += 1
                    size += os.path.getsize(os.path.join(root_dir, f))

            summary[category] = {
                "count": file_count,
                "size": size
            }

            total_size += size

    return summary, total_size
def generate_cybercrime_style_report():

    pdf_path = os.path.join(case_folder, "Cybercrime_Forensic_Report.pdf")
    doc = SimpleDocTemplate(pdf_path, pagesize=pagesizes.A4)
    elements = []
    styles = getSampleStyleSheet()

    # -------------------------------------------------
    # COVER PAGE
    # -------------------------------------------------
    elements.append(Paragraph("CYBERCRIME DIVISION", styles["Heading1"]))
    elements.append(Paragraph("DIGITAL FORENSIC EXAMINATION REPORT", styles["Heading2"]))
    elements.append(Spacer(1, 0.3 * inch))
    elements.append(Paragraph("Case Reference No: ____________________", styles["Normal"]))
    elements.append(Paragraph(f"Report Date: {datetime.now()}", styles["Normal"]))
    elements.append(PageBreak())

    # -------------------------------------------------
    # SECTION 1 – EVIDENCE DETAILS
    # -------------------------------------------------
    elements.append(Paragraph("1. EVIDENCE DETAILS", styles["Heading2"]))
    elements.append(Spacer(1, 0.2 * inch))

    try:
        model = run_adb("adb shell getprop ro.product.model").strip()
        version = run_adb("adb shell getprop ro.build.version.release").strip()
        serial = run_adb("adb get-serialno").strip()

        elements.append(Paragraph(f"Device Model: {model}", styles["Normal"]))
        elements.append(Paragraph(f"Android Version: {version}", styles["Normal"]))
        elements.append(Paragraph(f"Serial Number: {serial}", styles["Normal"]))
    except:
        elements.append(Paragraph("Device details unavailable.", styles["Normal"]))

    elements.append(PageBreak())

    # -------------------------------------------------
    # SECTION 2 – ACQUISITION PROCEDURE
    # -------------------------------------------------
    elements.append(Paragraph("2. ACQUISITION PROCEDURE", styles["Heading2"]))
    elements.append(Spacer(1, 0.2 * inch))
    elements.append(Paragraph(
        "The device was examined using logical acquisition via Android Debug Bridge (ADB). "
        "No modifications were performed on the source device. Extracted artifacts were "
        "hashed using SHA-256 to ensure integrity preservation.",
        styles["Normal"]
    ))
    elements.append(PageBreak())

    # -------------------------------------------------
    # SECTION 3 – CALL LOG ANALYSIS
    # -------------------------------------------------
    elements.append(Paragraph("3. CALL LOG ANALYSIS", styles["Heading2"]))
    elements.append(Spacer(1, 0.2 * inch))

    top10_path = os.path.join(case_folder, "05_Top_10_Call_Duration.txt")

    if os.path.exists(top10_path):
        with open(top10_path, "r", encoding="utf-8") as f:
            content = f.read()
        elements.append(Paragraph(content.replace("\n", "<br/>"), styles["Normal"]))
    else:
        elements.append(Paragraph("No call log analysis available.", styles["Normal"]))

    elements.append(PageBreak())

        # -------------------------------------------------
    # SECTION 4 – HASH VERIFICATION
    # -------------------------------------------------
    elements.append(Paragraph("4. HASH VERIFICATION (SHA-256)", styles["Heading2"]))
    elements.append(Spacer(1, 0.2 * inch))

    for file in os.listdir(case_folder):
        if file.endswith(".hash.txt"):
            hash_path = os.path.join(case_folder, file)

            with open(hash_path, "r", encoding="utf-8") as h:
                hash_content = h.read()

            elements.append(Paragraph(hash_content.replace("\n", "<br/>"), styles["Normal"]))
            elements.append(Spacer(1, 0.2 * inch))

# -------------------------------------------------
# SECTION 5 – WHATSAPP MEDIA EXTRACTION SUMMARY
# -------------------------------------------------
    elements.append(PageBreak())
    elements.append(Paragraph("5. WHATSAPP MEDIA EXTRACTION SUMMARY", styles["Heading2"]))
    elements.append(Spacer(1, 0.2 * inch))

    result = get_whatsapp_extraction_summary()

    if result:
        summary, total_size = result

        for category, data in summary.items():
            size_mb = round(data["size"] / (1024 * 1024), 2)

            elements.append(Paragraph(
                f"{category}: {data['count']} files | {size_mb} MB",
                styles["Normal"]
            ))
            elements.append(Spacer(1, 0.1 * inch))

        total_mb = round(total_size / (1024 * 1024), 2)

        elements.append(Spacer(1, 0.3 * inch))
        elements.append(Paragraph(
            f"Total WhatsApp Data Extracted: {total_mb} MB",
            styles["Heading3"]
        ))

    else:
        elements.append(Paragraph("No WhatsApp media extraction data    available.", styles["Normal"]))

    # -------------------------------------------------
    # CERTIFICATION
    # -------------------------------------------------
    elements.append(Paragraph("CERTIFICATION", styles["Heading2"]))
    elements.append(Spacer(1, 0.2 * inch))
    elements.append(Paragraph(
        "This report has been prepared based on the digital evidence made available "
        "for examination. The findings are derived from forensic analysis conducted "
        "using accepted digital forensic methodologies.",
        styles["Normal"]
    ))
    elements.append(Spacer(1, 0.5 * inch))
    elements.append(Paragraph("Examiner Signature: ____________________", styles["Normal"]))
    elements.append(Paragraph("Name & Designation: ____________________", styles["Normal"]))

    doc.build(elements)

    messagebox.showinfo("Success", "Cybercrime Style Report Generated Successfully")

    messagebox.showinfo("Success", "Call Logs + Top 10 Generated")




def generate_top10_call_duration(call_stats, call_duration):

    sorted_data = sorted(call_duration.items(),
                         key=lambda x: x[1],
                         reverse=True)[:10]






    report = "\n========== TOP 10 CALL CONTACTS (BY TOTAL DURATION) ==========\n"

    for rank, (number, total_sec) in enumerate(sorted_data, start=1):

        name = contacts_dict.get(number, "Unknown Contact")
        total_calls = call_stats.get(number, 0)
        total_minutes = round(total_sec / 60, 2)

        report += f"""
Rank {rank}
--------------------------------------------
Contact Name   : {name}
Phone Number   : {number}
Total Calls    : {total_calls}
Total Duration : {total_sec} seconds
Total Duration : {total_minutes} minutes
--------------------------------------------
"""

    save_file("05_Top_10_Call_Duration.txt", report)


    for rank, (number, total_sec) in enumerate(sorted_data, start=1):

        name = contacts_dict.get(number, "Unknown Contact")
        total_calls = call_stats.get(number, 0)
        total_minutes = round(total_sec / 60, 2)

        report += f"""
Rank {rank}
--------------------------------------------
Contact Name   : {name}
Phone Number   : {number}
Total Calls    : {total_calls}
Total Duration : {total_sec} seconds
Total Duration : {total_minutes} minutes
--------------------------------------------
"""

    save_file("05_Top_10_Call_Duration.txt", report)




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
# DEVICE STATUS INDICATOR
# =========================================================

def update_device_status():
    try:
        output = subprocess.run("adb devices", shell=True, capture_output=True, text=True).stdout
        lines = output.splitlines()
        devices = [l for l in lines[1:] if l.strip() and "device" in l and "unauthorized" not in l]

        if devices:
            device_status_label.config(text="● Device Connected", fg="green")

            model = run_adb("adb shell getprop ro.product.model").strip()
            version = run_adb("adb shell getprop ro.build.version.release").strip()
            serial = run_adb("adb get-serialno").strip()

            device_model_label.config(text=f"Model: {model}")
            android_version_label.config(text=f"Android Version: {version}")
            serial_label.config(text=f"Serial: {serial}")

        else:
            device_status_label.config(text="● No Device Connected", fg="red")
            device_model_label.config(text="Model: -")
            android_version_label.config(text="Android Version: -")
            serial_label.config(text="Serial: -")

    except:
        device_status_label.config(text="ADB Not Found", fg="red")

    root.after(3000, update_device_status)

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

# =========================================================
# DEVICE INFO DISPLAY
# =========================================================

device_frame = tk.LabelFrame(root, text="Device Information", padx=10, pady=10)
device_frame.pack(pady=10, fill="x")

device_status_label = tk.Label(device_frame, text="Checking device...", font=("Arial", 12, "bold"))
device_status_label.pack()

device_model_label = tk.Label(device_frame, text="Model: -", font=("Arial", 11))
device_model_label.pack()

android_version_label = tk.Label(device_frame, text="Android Version: -", font=("Arial", 11))
android_version_label.pack()

serial_label = tk.Label(device_frame, text="Serial: -", font=("Arial", 10))
serial_label.pack()

btn_frame = tk.Frame(root)
btn_frame.pack(pady=10)

actions = [
    ("1. Extract Device Metadata", extract_device_metadata),
    ("2. Extract Contact List", extract_contacts),
    ("3. Extract SMS", extract_sms_module),
    ("4. Extract Call Logs (With Top 10)", extract_calllog_module),
    ("5. List Installed Packages", lambda: save_file("07_apps.txt", run_adb("adb shell pm list packages -f"))),
    ("6. Dump System Notifications", lambda: save_file("08_notifications.txt", run_adb("adb shell dumpsys notification"))),
    ("7. Begin Media Extraction (WhatsApp)", start_whatsapp_extraction),
    ("8. STOP Extraction", lambda: globals().update(stop_flag=True)),
    ("9. Run AI Forensic Analysis", analyze_with_ai),
    ("10. Generate Cybercrime Department Report", generate_cybercrime_style_report),
]


for text, func in actions:
    tk.Button(btn_frame, text=text, width=45, command=func, pady=5).pack(pady=3)

progress = ttk.Progressbar(root, length=400, mode='determinate')
progress.pack(pady=20)

status_label = tk.Label(root, text="Ready", fg="blue")
status_label.pack()
update_device_status()
root.mainloop()
