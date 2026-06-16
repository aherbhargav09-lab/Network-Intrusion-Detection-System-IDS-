from datetime import datetime

LOG_FILE = "alerts.log"

def log_alert(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    alert = f"[{timestamp}] {message}"

    print(alert)

    with open(LOG_FILE, "a") as f:
        f.write(alert + "\n")
