import re
import csv
from datetime import datetime, timedelta
from collections import defaultdict

# --- CONFIGURATION ---
LOG_FILE = "access.log"
BLOCKLIST_FILE = "blocklist.csv"
FAILED_THRESHOLD = 5  # Max failed attempts before blocking
TRAVEL_WINDOW_HOURS = 1  # Timeframe for Impossible Travel

# Regex for Nginx Log: IP - - [Date] "Request" Status ...
LOG_PATTERN = r'(?P<ip>\d+\.\d+\.\d+\.\d+).*?\[(?P<timestamp>.*?)\] ".*?" (?P<status>\d+)'

# Mock GeoIP Database (In production, use an API or MaxMind)
def get_location(ip):
    # This is a placeholder. Real implementation would use:
    # requests.get(f"http://ip-api.com/json/{ip}").json()
    mock_db = {
        "1.1.1.1": "US",
        "2.2.2.2": "UK",
        "3.3.3.3": "CN"
    }
    return mock_db.get(ip, "Unknown")

def parse_logs():
    failed_attempts = defaultdict(int)  # IP: count
    user_logins = {}  # User/IP: {'time': datetime, 'country': str}
    suspicious_ips = set()

    with open(LOG_FILE, "r") as f:
        for line in f:
            match = re.search(LOG_PATTERN, line)
            if not match:
                continue

            ip = match.group('ip')
            status = match.group('status')
            # Example timestamp: 30/Apr/2026:14:00:01 +0000
            ts_str = match.group('timestamp').split(' ')[0]
            ts = datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S")

            # 1. Logic: Detect Brute Force (Repeated 401/403 errors)
            if status in ["401", "403"]:
                failed_attempts[ip] += 1
                if failed_attempts[ip] >= FAILED_THRESHOLD:
                    suspicious_ips.add((ip, "Brute Force Attempt"))

            # 2. Logic: Impossible Travel
            if status == "200":  # Successful login
                current_country = get_location(ip)
                
                if ip in user_logins:
                    last_login = user_logins[ip]
                    time_diff = ts - last_login['time']
                    
                    if current_country != last_login['country'] and time_diff < timedelta(hours=TRAVEL_WINDOW_HOURS):
                        suspicious_ips.add((ip, f"Impossible Travel: {last_login['country']} -> {current_country}"))
                
                # Update last known login for this entity
                user_logins[ip] = {'time': ts, 'country': current_country}

    return suspicious_ips

def export_blocklist(threats):
    with open(BLOCKLIST_FILE, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["IP Address", "Reason", "Detected At"])
        for ip, reason in threats:
            writer.writerow([ip, reason, datetime.now().strftime("%Y-%m-%d %H:%M:%S")])
    print(f"[+] Successfully exported {len(threats)} IPs to {BLOCKLIST_FILE}")

if __name__ == "__main__":
    print("[*] Starting Log Analysis...")
    detected_threats = parse_logs()
    if detected_threats:
        export_blocklist(detected_threats)
    else:
        print("[-] No suspicious activity detected.")