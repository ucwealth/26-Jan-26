import os
import requests
from datetime import datetime
import time

FILE_PATH = "daily_log.txt"
ERROR_LOG = "error_log.txt"

def fetch_quote(retries=1, delay=5):
    url = "https://api.quotable.io/random"
    for attempt in range(retries + 1):
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            data = response.json()
            return f"{data['content']} — {data['author']}"
        except Exception as e:
            if attempt < retries:
                time.sleep(delay)
            else:
                with open(ERROR_LOG, "a") as f:
                    f.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - Failed to fetch quote: {e}\n")
                return f"Could not fetch quote today: {e}"

quote = fetch_quote(retries=1)
line = f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - {quote}\n"

if os.path.exists(FILE_PATH):
    with open(FILE_PATH, "r") as f:
        content = f.read()
else:
    content = ""

with open(FILE_PATH, "w") as f:
    f.write(content + line)

print(f"Added line: {line.strip()}")
