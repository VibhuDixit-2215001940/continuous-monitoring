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
import wmi
import requests
import socket
import threading
import time
import re

COLLECTOR = "http://127.0.0.1:5000/alert"
HOST = socket.gethostname()


c = wmi.WMI()

print("[+] Monitoring FAILED logins only (Event ID 4625)")

login_watcher = c.Win32_NTLogEvent.watch_for(
    notification_type="Creation",
    Logfile="Security",
    EventCode="4625"
)

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
                print(f"[+] HID device ignored → {pnp.Name}")
                continue

            if "receiver" in device_name:
                print(f"[+] USB Receiver ignored → {pnp.Name}")
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

usb_thread = threading.Thread(target=monitor_usb_devices, daemon=True)
usb_thread.start()

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
