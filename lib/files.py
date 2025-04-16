import os
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes

# Memory file store and valuables
filestore = {"f1": b"Test File"}
valuables = []

# DH-derived keying material (set via set_keys_from_secret)
shared_secret = None
encryption_key = None
mac_key = None
BLOCK_SIZE = 16


def set_keys_from_secret(secret: bytes):
    """
    Derives AES and MAC keys from DH shared secret.
    """
    global shared_secret, encryption_key, mac_key
    shared_secret = secret
    encryption_key = SHA256.new(secret + b"enc").digest()
    mac_key = SHA256.new(secret + b"mac").digest()


def save_valuable(data):
    valuables.append(data)


def encrypt_for_master(data: bytes) -> bytes:
    """
    Encrypt and HMAC the data for the botmaster.
    Format: [IV || ciphertext || HMAC]
    """
    iv = get_random_bytes(BLOCK_SIZE)
    cipher = AES.new(encryption_key, AES.MODE_CBC, iv)
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    padded = data + bytes([pad_len] * pad_len)
    ciphertext = cipher.encrypt(padded)

    tag = HMAC.new(mac_key, iv + ciphertext, digestmod=SHA256).digest()
    return iv + ciphertext + tag


def decrypt_from_master(data: bytes) -> bytes:
    """
    Decrypt file from pastebot if HMAC matches.
    """
    iv = data[:BLOCK_SIZE]
    ciphertext = data[BLOCK_SIZE:-32]
    recv_mac = data[-32:]

    h = HMAC.new(mac_key, iv + ciphertext, digestmod=SHA256)
    h.verify(recv_mac)

    cipher = AES.new(encryption_key, AES.MODE_CBC, iv)
    padded = cipher.decrypt(ciphertext)
    pad_len = padded[-1]
    return padded[:-pad_len]


def upload_valuables_to_pastebot(fn):
    """
    Uploads encrypted valuables to pastebot.net.
    """
    valuable_data = "\n".join(valuables).encode("ascii")
    encrypted = encrypt_for_master(valuable_data)

    with open(os.path.join("pastebot.net", fn), "wb") as f:
        f.write(encrypted)

    print("Saved valuables to pastebot.net/%s for the botnet master" % fn)


def verify_file(f: bytes) -> bool:
    """
    Confirms authenticity of botmaster files using HMAC check.
    """
    if mac_key is None or encryption_key is None:
        print("[!] Keys not initialized. Please run 'p2p echo' first.")
        return False

    try:
        _ = decrypt_from_master(f)
        return True
    except Exception as e:
        print("[!] File verification failed:", str(e))
        return False


def process_file(fn, f):
    if verify_file(f):
        filestore[fn] = f
        print("Stored the received file as %s" % fn)
    else:
        print("The file has not been signed by the botnet master")


def download_from_pastebot(fn):
    """
    Simulates downloading a file from pastebot.net.
    """
    path = os.path.join("pastebot.net", fn)
    if not os.path.exists(path):
        print("The given file doesn't exist on pastebot.net")
        return

    with open(path, "rb") as f:
        data = f.read()
    process_file(fn, data)


def p2p_download_file(sconn):
    """
    Receive file from another bot via P2P.
    """
    fn = sconn.recv().decode("ascii")
    f = sconn.recv()
    print("Receiving %s via P2P" % fn)
    process_file(fn, f)


def p2p_upload_file(sconn, fn):
    """
    Send file to another bot via P2P.
    """
    if fn not in filestore:
        print("That file doesn't exist in the botnet's filestore")
        return
    print("Sending %s via P2P" % fn)
    sconn.send(fn.encode("ascii"))
    sconn.send(filestore[fn])


def run_file(f):
    # Placeholder: interpret and execute payloads (if implemented)
    pass
