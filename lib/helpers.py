import string
from Crypto.Hash import HMAC, SHA256
import secrets

def read_hex(data):
    """
    Convert hex string (with or without spaces/newlines) to integer.
    """
    data = data.replace(" ", "").replace("\n", "")
    return int(data, 16)


def generate_random_string(alphabet=None, length=8, exact=True):
    """
    Generate a secure random string using a CSPRNG.
    """
    if not alphabet:
        alphabet = string.ascii_letters + string.digits

    return ''.join(secrets.choice(alphabet) for _ in range(length))


def appendMac(data: bytes, secret: bytes) -> bytes:
    """
    Appends HMAC-SHA256 to the data.
    """
    h = HMAC.new(secret, digestmod=SHA256)
    h.update(data)
    return data + h.digest()


def macCheck(data: bytes, received_mac: bytes, secret: bytes) -> bool:
    """
    Verifies the HMAC of the data.
    """
    h = HMAC.new(secret, digestmod=SHA256)
    h.update(data)
    try:
        h.verify(received_mac)
        return True
    except ValueError:
        return False


def appendSalt(data: bytes, length: int = 8) -> bytes:
    """
    Appends a random salt of `length` bytes to the data.
    """
    return data + secrets.token_bytes(length)
