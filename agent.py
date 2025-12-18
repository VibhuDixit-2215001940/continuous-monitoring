# import wmi
# import requests
# import socket

# COLLECTOR = "http://127.0.0.1:5000/alert"
# HOST = socket.gethostname()

# c = wmi.WMI()

# print("[+] Monitoring FAILED logins only (Event ID 4625)")

# watcher = c.Win32_NTLogEvent.watch_for(
#     notification_type="Creation",
#     Logfile="Security",
#     EventCode="4625"
# )

# while True:
#     try:
#         e = watcher()   # blocks until failed login happens
#         requests.post(COLLECTOR, json={
#             "host": HOST,
#             "event": "FAILED_LOGIN",
#             "event_id": 4625,
#             "time": e.TimeGenerated,
#             "user": e.InsertionStrings
#         }, timeout=2)

#         print("🚨 Failed login detected → sent to collector")

#     except Exception as ex:
#         print("[!] Error:", ex)


# ------------------------------------V2--------------------------------
# import wmi
# import requests
# import socket
# import threading
# import time
# import re

# COLLECTOR = "http://127.0.0.1:5000/alert"
# HOST = socket.gethostname()


# c = wmi.WMI()

# print("[+] Monitoring FAILED logins only (Event ID 4625)")

# login_watcher = c.Win32_NTLogEvent.watch_for(
#     notification_type="Creation",
#     Logfile="Security",
#     EventCode="4625"
# )

# def monitor_usb_devices():
#     import pythoncom
#     pythoncom.CoInitialize()  

#     usb_wmi = wmi.WMI()

#     usb_watcher = usb_wmi.watch_for(
#         notification_type="Creation",
#         wmi_class="Win32_USBControllerDevice"
#     )

#     print("[+] Monitoring USB insertions")

#     while True:
#         try:
#             usb_event = usb_watcher()

#             dependent = usb_event.Dependent

#             match = re.search(r'DeviceID="([^"]+)"', dependent)
#             if not match:
#                 continue

#             device_id = match.group(1).replace("\\", "\\\\")

#             pnp_devices = usb_wmi.query(
#                 f"SELECT * FROM Win32_PnPEntity WHERE DeviceID='{device_id}'"
#             )

#             if not pnp_devices:
#                 continue

#             pnp = pnp_devices[0]

#             device_name = (pnp.Name or "").lower()
#             pnp_class = (pnp.PNPClass or "").lower()

#             if pnp_class == "hidclass":
#                 print(f"[+] HID device ignored → {pnp.Name}")
#                 continue

#             if "receiver" in device_name:
#                 print(f"[+] USB Receiver ignored → {pnp.Name}")
#                 continue

#             requests.post(COLLECTOR, json={
#                 "host": HOST,
#                 "event": "USB_DEVICE_INSERTED",
#                 "device_name": pnp.Name,
#                 "pnp_class": pnp.PNPClass,
#                 "device_id": pnp.DeviceID,
#                 "threat": "POTENTIAL_USB_STORAGE"
#             }, timeout=2)

#             print(f"🚨 USB storage detected → {pnp.Name}")

#         except Exception as ex:
#             print("[!] USB Error:", ex)
#             time.sleep(1)

# usb_thread = threading.Thread(target=monitor_usb_devices, daemon=True)
# usb_thread.start()

# while True:
#     try:
#         e = login_watcher()
#         requests.post(COLLECTOR, json={
#             "host": HOST,
#             "event": "FAILED_LOGIN",
#             "event_id": 4625,
#             "time": e.TimeGenerated,
#             "user": e.InsertionStrings
#         }, timeout=2)

#         print("🚨 Failed login detected → sent to collector")

#     except Exception as ex:
#         print("[!] Login Error:", ex)
#         time.sleep(1)

#-------------------------------V3----------------------------------
import wmi
import requests
import socket
import threading
import time
import re

COLLECTOR = "http://127.0.0.1:5000/alert"
HOST = socket.gethostname()

# ================= FAILED LOGIN WATCHER (UNCHANGED) =================

c = wmi.WMI()

print("[+] Monitoring FAILED logins only (Event ID 4625)")

login_watcher = c.Win32_NTLogEvent.watch_for(
    notification_type="Creation",
    Logfile="Security",
    EventCode="4625"
)

# ================= USB MONITOR THREAD =================

def monitor_usb_devices():
    import pythoncom
    pythoncom.CoInitialize()

    usb_wmi = wmi.WMI()
    usb_watcher = usb_wmi.watch_for(
        notification_type="Creation",
        wmi_class="Win32_USBControllerDevice"
    )

    print("[+] Monitoring USB insertions")

    while True:
        try:
            usb_event = usb_watcher()
            dependent = usb_event.Dependent

            match = re.search(r'DeviceID="([^"]+)"', dependent)
            if not match:
                continue

            device_id = match.group(1).replace("\\", "\\\\")
            pnp_devices = usb_wmi.query(
                f"SELECT * FROM Win32_PnPEntity WHERE DeviceID='{device_id}'"
            )

            if not pnp_devices:
                continue

            pnp = pnp_devices[0]
            device_name = (pnp.Name or "").lower()
            pnp_class = (pnp.PNPClass or "").lower()

            if pnp_class == "hidclass":
                continue

            if "receiver" in device_name:
                continue

            requests.post(COLLECTOR, json={
                "host": HOST,
                "event": "USB_DEVICE_INSERTED",
                "device_name": pnp.Name,
                "pnp_class": pnp.PNPClass,
                "device_id": pnp.DeviceID,
                "threat": "POTENTIAL_USB_STORAGE"
            }, timeout=2)

            print(f"🚨 USB storage detected → {pnp.Name}")

        except Exception as ex:
            print("[!] USB Error:", ex)
            time.sleep(1)

# ================= POWERSHELL SUSPICIOUS FLAGS DETECTION =================

def monitor_powershell_flags_wmi():
    import pythoncom
    pythoncom.CoInitialize()

    ps_wmi = wmi.WMI()

    print("[+] Monitoring PowerShell suspicious flags (WMI/ETW)")

    suspicious_regex = re.compile(
        r"("
        r"-enc|-encodedcommand|"
        r"-nop|-noni|-w\s+hidden|"
        r"-exec\s+bypass|-executionpolicy\s+bypass|"
        r"frombase64string|\[convert\]::frombase64string|"
        r"invoke-expression|iex|"
        r"invoke-webrequest|iwr|wget|curl|downloadstring|downloadfile|"
        r"new-object\s+net\.webclient|"
        r"amsiutils|amsiinitfailed|amsiscanbuffer|"
        r"\[reflection\.assembly\]|gettype\(|load\(|"
        r"securestringtobstr|get-credential|mimikatz|dumpcreds|"
        r"schtasks|new-scheduledtask|register-scheduledtask|"
        r"invoke-command|new-pssession|enter-pssession"
        r")",
        re.IGNORECASE
    )


    ps_watcher = ps_wmi.watch_for(
        notification_type="Creation",
        wmi_class="Win32_ProcessStartTrace"
    )

    while True:
        try:
            e = ps_watcher()

            process_name = (e.ProcessName or "").lower()
            pid = e.ProcessID

            if process_name not in ("powershell.exe", "pwsh.exe"):
                continue

            # 🔥 Get REAL command line from Win32_Process
            procs = ps_wmi.query(
                f"SELECT CommandLine FROM Win32_Process WHERE ProcessId={pid}"
            )

            if not procs or not procs[0].CommandLine:
                continue

            command_line = procs[0].CommandLine

            if suspicious_regex.search(command_line):
                requests.post(COLLECTOR, json={
                    "host": HOST,
                    "event": "POWERSHELL_SUSPICIOUS_FLAGS",
                    "process": process_name,
                    "pid": pid,
                    "command_line": command_line,
                    "threat": "POWERSHELL_OBFUSCATION"
                }, timeout=2)

                print("🚨 Suspicious PowerShell execution detected")

        except Exception as ex:
            print("[!] PowerShell WMI Error:", ex)
            time.sleep(1)


# ================= START THREADS =================

usb_thread = threading.Thread(target=monitor_usb_devices, daemon=True)
usb_thread.start()

ps_thread = threading.Thread(target=monitor_powershell_flags_wmi, daemon=True)
ps_thread.start()

# ================= MAIN THREAD = FAILED LOGIN =================

while True:
    try:
        e = login_watcher()
        requests.post(COLLECTOR, json={
            "host": HOST,
            "event": "FAILED_LOGIN",
            "event_id": 4625,
            "time": e.TimeGenerated,
            "user": e.InsertionStrings
        }, timeout=2)

        print("🚨 Failed login detected → sent to collector")

    except Exception as ex:
        print("[!] Login Error:", ex)
        time.sleep(1)
