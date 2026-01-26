import os
import random
from datetime import datetime

BASE_DIR = os.path.dirname(__file__)
FILE_PATH = os.path.join(BASE_DIR, "daily_log.txt")
ERROR_LOG = os.path.join(BASE_DIR, "error_log.txt")
RANDOM_TIME_FILE = os.path.join(BASE_DIR, ".random_time")

if os.path.exists(RANDOM_TIME_FILE):
    with open(RANDOM_TIME_FILE, "r") as f:
        rand_time = f.read().strip()
else:
    rand_time = "Unknown"

quotes = [
    "The early bird catches the worm. — Unknown",
    "Stay hungry, stay foolish. — Steve Jobs",
    "Actions speak louder than words. — Unknown",
    "Success is not final, failure is not fatal: it is the courage to continue that counts. — Winston Churchill",
    "Believe you can and you're halfway there. — Theodore Roosevelt",
    "Do what you can, with what you have, where you are. — Theodore Roosevelt",
    "Happiness is not something ready made. It comes from your own actions. — Dalai Lama",
    "In the middle of every difficulty lies opportunity. — Albert Einstein",
    "The only way to do great work is to love what you do. — Steve Jobs",
    "It always seems impossible until it's done. — Nelson Mandela"
]

quote = random.choice(quotes)

line = f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} (random time: {rand_time}) - {quote}\n"

try:
    with open(FILE_PATH, "a") as f:
        f.write(line)
    print(f"Added line: {line.strip()}")
except Exception as e:
    with open(ERROR_LOG, "a") as f:
        f.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - Failed to write quote: {e}\n")
    print(f"Failed to write quote: {e}")
