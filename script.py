import win32evtlog
import csv
from datetime import datetime, timedelta
from collections import defaultdict

# --- CONFIGURATION ---
LOG_TYPE = "Security"
BLOCKLIST_FILE = "windows_blocklist.csv"
FAILED_THRESHOLD = 5
TRAVEL_WINDOW_HOURS = 1

def get_location(ip):
    # Placeholder: In a real SOC environment, use MaxMind or ip-api.com
    mock_db = {"10.0.0.1": "US", "192.168.1.50": "FR"}
    return mock_db.get(ip, "Unknown")

def parse_windows_logs():
    server = 'localhost'
    handle = win32evtlog.OpenEventLog(server, LOG_TYPE)
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    
    failed_attempts = defaultdict(int)
    user_logins = {} # Username: {'time': ts, 'country': country}
    threats = set()

    print(f"[*] Scanning {LOG_TYPE} logs...")

    while True:
        events = win32evtlog.ReadEventLog(handle, flags, 0)
        if not events:
            break

        for event in events:
            # Event ID 4625 = Failed Login
            if event.EventID == 4625:
                # String index 18 is typically the Source Network Address in 4625 events
                try:
                    ip = event.StringInserts[19] 
                    if ip and ip != "-":
                        failed_attempts[ip] += 1
                        if failed_attempts[ip] >= FAILED_THRESHOLD:
                            threats.add((ip, "Brute Force (Event 4625)"))
                except IndexError:
                    continue

            # Event ID 4624 = Successful Login
            elif event.EventID == 4624:
                try:
                    username = event.StringInserts[5]
                    ip = event.StringInserts[18]
                    ts = event.TimeGenerated
                    
                    if ip and ip != "-" and "127.0.0.1" not in ip:
                        country = get_location(ip)
                        
                        if username in user_logins:
                            last = user_logins[username]
                            time_diff = ts - last['time']
                            
                            if country != last['country'] and time_diff < timedelta(hours=TRAVEL_WINDOW_HOURS):
                                threats.add((ip, f"Impossible Travel: {username} from {last['country']} to {country}"))
                        
                        user_logins[username] = {'time': ts, 'country': country}
                except IndexError:
                    continue

    return threats

def export_threats(threats):
    if not threats:
        print("[-] No suspicious activity found.")
        return

    with open(BLOCKLIST_FILE, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Source IP", "Reason", "Timestamp"])
        for ip, reason in threats:
            writer.writerow([ip, reason, datetime.now()])
    print(f"[+] Exported {len(threats)} threats to {BLOCKLIST_FILE}")

if __name__ == "__main__":
    # Note: Must run as Administrator to access Security Logs
    try:
        detected = parse_windows_logs()
        export_threats(detected)
    except Exception as e:
        print(f"[!] Error: {e}. Did you run as Administrator?")