import os
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA512
from Crypto.Random import get_random_bytes

# Local data store for botnet content
filestore = {"f1": b"Test File"}
valuables = []

# Session-level crypto state
shared_secret = None
enc_key = None
auth_key = None
BLOCK_SIZE = 16

def set_keys_from_secret(secret: bytes): #Task 1: Derives AES (enc) and HMAC (auth) keys from the shared DH secret.
    global shared_secret, enc_key, auth_key
    shared_secret = secret
    enc_key = HMAC.new(secret, b"enc", digestmod=SHA512).digest()[:32]
    auth_key = HMAC.new(secret, b"mac", digestmod=SHA512).digest()[:32]

    

def save_valuable(entry):#Task 4:Appends a stolen credential or mined result to the local 'valuables' list.
    valuables.append(entry)


def encrypt_for_master(data: bytes) -> bytes: # Encrypts data using AES-CBC and appends HMAC for integrity (IV + ciphertext + tag)
    iv = get_random_bytes(BLOCK_SIZE)
    cipher = AES.new(enc_key, AES.MODE_CBC, iv)

    # PKCS7-style padding
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    padded_data = data + bytes([pad_len] * pad_len)

    encrypted = cipher.encrypt(padded_data)
    tag = HMAC.new(auth_key, iv + encrypted, digestmod=SHA512).digest()
    return iv + encrypted + tag


def decrypt_from_master(blob: bytes) -> bytes: #Verifies HMAC and decrypts AES-CBC ciphertext from the master (raises if invalid)
    iv = blob[:BLOCK_SIZE]
    encrypted = blob[BLOCK_SIZE:-64]
    tag = blob[-64:]

    verifier = HMAC.new(auth_key, iv + encrypted, digestmod=SHA512)
    verifier.verify(tag)

    cipher = AES.new(enc_key, AES.MODE_CBC, iv)
    padded = cipher.decrypt(encrypted)
    return padded[:-padded[-1]]  # Remove padding


def upload_valuables_to_pastebot(filename): # Encrypts all valuables and saves them to a pastebot.net file
    data = "\n".join(valuables).encode("ascii")
    encrypted_blob = encrypt_for_master(data)

    os.makedirs("pastebot.net", exist_ok=True)
    with open(os.path.join("pastebot.net", filename), "wb") as f:
        f.write(encrypted_blob)

    print("Uploaded valuables to pastebot.net/%s" % filename)


def verify_file(blob: bytes) -> bool: # Validates a file's authenticity using HMAC (Task 3)
    if enc_key is None or auth_key is None:
        print("[!] Keys not set. Use 'p2p echo' to negotiate keys.")
        return False

    try:
        _ = decrypt_from_master(blob)
        return True
    except Exception as err:
        print("[!] Invalid file: %s" % str(err))
        return False


def process_file(filename, blob):# Verifies and stores a received file from master or peer
    if verify_file(blob):
        filestore[filename] = blob
        print("Stored file as '%s'" % filename)
    else:
        print("Rejected file: signature could not be verified")


def download_from_pastebot(filename):# Loads and processes a file from pastebot.net
    path = os.path.join("pastebot.net", filename)
    if not os.path.exists(path):
        print("pastebot.net/%s not found" % filename)
        return

    with open(path, "rb") as f:
        blob = f.read()
    process_file(filename, blob)


def p2p_download_file(sconn):# Receives and verifies a signed file from a peer bot (Tasks 2 & 3)
    fname = sconn.recv().decode("ascii")
    content = sconn.recv()
    print("P2P downloading: %s" % fname)
    process_file(fname, content)


def p2p_upload_file(sconn, fname):# Sends a file from the local store to a connected peer
    if fname not in filestore:
        print("File '%s' not found in local storage." % fname)
        return

    print("Sending '%s' to peer..." % fname)
    sconn.send(fname.encode("ascii"))
    sconn.send(filestore[fname])


def run_file(blob):# Executes a verified command or payload 
    pass


if __name__ == "__main__":
    test = b"SkyNet Confidential Command Payload"
    blob = encrypt_for_master(test)

    os.makedirs("pastebot.net", exist_ok=True)
    with open("pastebot.net/hello.signed", "wb") as f:
        f.write(blob)
    print("Signed file written to pastebot.net/hello.signed")
