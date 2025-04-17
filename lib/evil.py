import time
import secrets
from lib.helpers import generate_random_string


def bitcoin_mine(): # Simulates mining by showing animation and returns a fake Bitcoin address starting with '1' or '3'
    spinner = "\\|/-"
    for i in range(8):
        print(f"\r{spinner[i % len(spinner)]}", end="", flush=True)
        time.sleep(0.1)
    print()
    return secrets.choice("13") + generate_random_string(length=30)


def harvest_user_pass(): # Simulates credential theft by choosing a random name and generating a secure 10-char password
    names = "Bob Tim Ben Adam Lois Julie Daniel Lucy Sam Stephen Matt Luke Jenny Becca".split()
    username = secrets.choice(names)
    password = generate_random_string(length=10)
    return username, password
