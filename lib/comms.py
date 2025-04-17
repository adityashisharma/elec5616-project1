import struct
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA512

from dh import generate_keypair, compute_shared_secret
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


class SecureChannel: # Handles secure communication using AES encryption, HMAC integrity, and replay protection.
    def __init__(self, socket, is_client=False, is_server=False, debug=False):
        self.socket = socket
        self.is_client = is_client
        self.is_server = is_server
        self.debug = debug

        # Security parameters
        self._secret = None
        self._enc_key = None
        self._mac_key = None
        self._iv_seed = None

        self._seq = 0
        self._replay_check = set()

        # Track most recent sent and received messages
        self._outgoing = None
        self._incoming = None

        self._negotiate_keys()

    # Secure HKDF derivation for different roles (encryption, mac, iv)
    def _extract(self, seed: bytes, label: bytes, size: int) -> bytes:
        salt_value = SHA512.new(b'unique-salt-skynet-v2025').digest()
        expander = HKDF(
            algorithm=hashes.SHA512(),
            length=size,
            salt=salt_value,
            info=label,
            backend=default_backend()
        )
        return expander.derive(seed)

    # Perform key exchange and derive session keys
    def _negotiate_keys(self):
        pub_local, priv_local = generate_keypair()

        if self.is_client or self.is_server:
            self._push_data(bytes(str(pub_local), "utf-8"))
            pub_remote = int(self._pull_data())
            self._secret = compute_shared_secret(pub_remote, priv_local)

            self._enc_key = self._extract(self._secret, b"label-aes", 32)
            self._mac_key = self._extract(self._secret, b"label-hmac", 32)
            self._iv_seed = self._extract(self._secret, b"label-iv", 32)

            if self.debug:
                print("[keygen] DH secret:", self._secret.hex())
                print("[keygen] AES key:", self._enc_key.hex())
                print("[keygen] MAC key:", self._mac_key.hex())
                print("[keygen] IV seed:", self._iv_seed.hex())

    # Generate a fresh IV from base and incrementing counter
    def _next_iv(self) -> bytes:
        digest = HMAC.new(self._iv_seed, self._seq.to_bytes(8, 'big'), digestmod=SHA512).digest()
        self._seq += 1
        return digest[:16]

    # Generate a HMAC tag for a message
    def _tag(self, payload: bytes) -> bytes:
        mac = HMAC.new(self._mac_key, digestmod=SHA512)
        mac.update(payload)
        return mac.digest()

    # Validate HMAC tag
    def _verify_tag(self, msg: bytes, tag: bytes):
        verifier = HMAC.new(self._mac_key, digestmod=SHA512)
        verifier.update(msg)
        verifier.verify(tag)

    # Encrypt and send data with integrity tag
    def send(self, content: bytes):
        if self._secret is None:
            raise RuntimeError("Session key missing")

        nonce = self._next_iv()
        encryptor = AES.new(self._enc_key, AES.MODE_CTR, nonce=nonce[:8])
        encrypted = encryptor.encrypt(content)
        signature = self._tag(encrypted)

        packet = encrypted + signature
        length = struct.pack("H", len(packet))
        self.socket.sendall(length + packet)

        self._outgoing = packet

        if self.debug:
            print("[tx] Nonce:", nonce.hex())
            print("[tx] Ciphertext:", encrypted.hex())
            print("[tx] HMAC:", signature.hex())

    # Receive and decrypt data
    def recv(self) -> bytes:
        hdr = self.socket.recv(struct.calcsize("H"))
        total = struct.unpack("H", hdr)[0]
        blob = self.socket.recv(total)

        message = blob[:-64]
        tag = blob[-64:]

        # Detect replayed packets
        if blob in self._replay_check:
            raise ValueError("Duplicate packet detected")
        self._replay_check.add(blob)

        self._verify_tag(message, tag)

        nonce = self._next_iv()
        decryptor = AES.new(self._enc_key, AES.MODE_CTR, nonce=nonce[:8])
        plain = decryptor.decrypt(message)

        self._incoming = blob

        if self.debug:
            print("[rx] Nonce:", nonce.hex())
            print("[rx] Ciphertext:", message.hex())
            print("[rx] HMAC:", tag.hex())
            print("[rx] Plaintext:", plain)

        return plain

    # Re-send last message sent (for testing)
    def echo_last_out(self):
        if self._outgoing:
            self.socket.sendall(struct.pack("H", len(self._outgoing)) + self._outgoing)
        else:
            print("[echo] No sent message to replay.")

    # Re-send last received packet (for testing)
    def echo_last_in(self):
        if self._incoming:
            self.socket.sendall(struct.pack("H", len(self._incoming)) + self._incoming)
        else:
            print("[echo] No received packet to replay.")

    # Raw sender with 2-byte header
    def _push_data(self, data: bytes):
        prefix = struct.pack("H", len(data))
        self.socket.sendall(prefix + data)

    # Raw receiver with length header
    def _pull_data(self) -> bytes:
        size_info = self.socket.recv(struct.calcsize("H"))
        size = struct.unpack("H", size_info)[0]
        return self.socket.recv(size)

    def close(self):
        self.socket.close()
