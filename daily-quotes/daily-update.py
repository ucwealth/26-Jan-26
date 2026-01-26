import os
import requests
from datetime import datetime
import time

BASE_DIR = os.path.dirname(__file__)
FILE_PATH = os.path.join(BASE_DIR, "daily_log.txt")
ERROR_LOG = os.path.join(BASE_DIR, "error_log.txt")
RANDOM_TIME_FILE = os.path.join(BASE_DIR, ".random_time")

if os.path.exists(RANDOM_TIME_FILE):
    with open(RANDOM_TIME_FILE, "r") as f:
        rand_time = f.read().strip()
else:
    rand_time = "Unknown"

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
line = f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} (random time: {rand_time}) - {quote}\n"


with open(FILE_PATH, "a") as f:
    f.write(line)

print(f"Added line: {line.strip()}")

