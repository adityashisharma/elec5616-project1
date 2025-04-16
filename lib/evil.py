# Secure botnet actions (e.g. password stealing, mining)
import time
import secrets
from lib.helpers import generate_random_string

def bitcoin_mine():
    """
    Simulates mining a fake bitcoin address.
    Bitcoin addresses usually start with '1' or '3'.
    """
    frames = "\\|/-"
    for i in range(8):
        print("\r%c" % frames[i % len(frames)], end="")
        time.sleep(0.1)
    print()
    # Secure random prefix and address
    return secrets.choice("13") + generate_random_string(length=30)


def harvest_user_pass():
    """
    Simulates harvesting a random username + password pair.
    """
    names = [
        "Bob", "Tim", "Ben", "Adam", "Lois", "Julie", "Daniel",
        "Lucy", "Sam", "Stephen", "Matt", "Luke", "Jenny", "Becca"
    ]
    username = secrets.choice(names)
    password = generate_random_string(length=10)
    return username, password
