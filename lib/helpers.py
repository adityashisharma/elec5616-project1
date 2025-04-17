import string
import secrets
from Crypto.Hash import HMAC, SHA512


def read_hex(src: str) -> int:  # Converts hex (with whitespace) into integer
    cleaned = src.replace(" ", "").replace("\n", "")
    return int(cleaned, 16)


def generate_random_string(alphabet=None, length=8):  # Generates a secure random string
    charset = alphabet or (string.ascii_letters + string.digits)
    return ''.join(secrets.choice(charset) for _ in range(length))


def attach_mac(payload: bytes, key: bytes) -> bytes:  # Appends HMAC-SHA512 to data
    mac = HMAC.new(key, digestmod=SHA512)
    mac.update(payload)
    return payload + mac.digest()


def validate_mac(msg: bytes, tag: bytes, key: bytes) -> bool:  # Verifies HMAC using secret key
    mac = HMAC.new(key, digestmod=SHA512)
    mac.update(msg)
    try:
        mac.verify(tag)
        return True
    except ValueError:
        return False


def salt_data(msg: bytes, salt_len: int = 8) -> bytes:  # Appends secure random salt to data
    return msg + secrets.token_bytes(salt_len)
