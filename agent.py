import wmi
import requests
import socket

COLLECTOR = "http://127.0.0.1:5000/alert"
HOST = socket.gethostname()

c = wmi.WMI()

print("[+] Monitoring FAILED logins only (Event ID 4625)")

watcher = c.Win32_NTLogEvent.watch_for(
    notification_type="Creation",
    Logfile="Security",
    EventCode="4625"
)

while True:
    try:
        e = watcher()   # blocks until failed login happens
        requests.post(COLLECTOR, json={
            "host": HOST,
            "event": "FAILED_LOGIN",
            "event_id": 4625,
            "time": e.TimeGenerated,
            "user": e.InsertionStrings
        }, timeout=2)

        print("🚨 Failed login detected → sent to collector")

    except Exception as ex:
        print("[!] Error:", ex)
