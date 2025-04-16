import struct
import os
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes

from dh import create_dh_key, calculate_dh_secret


class SecureChannel:
    def __init__(self, conn, client=False, server=False, verbose=False):
        self.conn = conn
        self.client = client
        self.server = server
        self.verbose = verbose

        self.shared_secret = None
        self.aes_key = None
        self.mac_key = None
        self.used_nonces = set()

        self.initiate_session()

    def initiate_session(self):
        """
        Perform Diffie-Hellman key exchange and derive AES and MAC keys.
        """
        my_public, my_private = create_dh_key()

        # Exchange public keys
        if self.client or self.server:
            self._send_raw(bytes(str(my_public), "ascii"))
            their_public = int(self._recv_raw())

            # Compute shared secret
            self.shared_secret = calculate_dh_secret(their_public, my_private)

            # Derive separate keys for encryption and MAC
            self.aes_key = SHA256.new(self.shared_secret + b"enc").digest()
            self.mac_key = SHA256.new(self.shared_secret + b"mac").digest()

            if self.verbose:
                print("Shared Secret (hash):", self.shared_secret.hex())
                print("Derived AES key:", self.aes_key.hex())
                print("Derived MAC key:", self.mac_key.hex())

    def pad(self, data):
        pad_len = 16 - (len(data) % 16)
        return data + bytes([pad_len] * pad_len)

    def unpad(self, data):
        pad_len = data[-1]
        return data[:-pad_len]

    def encrypt_and_mac(self, message: bytes, nonce: bytes) -> bytes:
        """
        Format: nonce (8B) || IV (16B) || ciphertext || HMAC (32B)
        """
        if nonce in self.used_nonces:
            raise ValueError("Replay attack detected!")

        self.used_nonces.add(nonce)
        iv = get_random_bytes(16)

        cipher = AES.new(self.aes_key, AES.MODE_CBC, iv)
        padded = self.pad(message)
        ciphertext = cipher.encrypt(padded)

        tag = HMAC.new(self.mac_key, nonce + iv + ciphertext, digestmod=SHA256).digest()

        return nonce + iv + ciphertext + tag

    def decrypt_and_verify(self, data: bytes) -> bytes:
        nonce = data[:8]
        iv = data[8:24]
        ciphertext = data[24:-32]
        recv_mac = data[-32:]

        if nonce in self.used_nonces:
            raise ValueError("Replay attack detected!")

        self.used_nonces.add(nonce)

        # Verify MAC
        tag = HMAC.new(self.mac_key, nonce + iv + ciphertext, digestmod=SHA256)
        tag.verify(recv_mac)

        # Decrypt
        cipher = AES.new(self.aes_key, AES.MODE_CBC, iv)
        padded = cipher.decrypt(ciphertext)
        return self.unpad(padded)

    def send(self, data: bytes):
        """
        Securely send encrypted and authenticated data.
        """
        if not self.shared_secret:
            raise Exception("Secure session not established")

        nonce = get_random_bytes(8)
        encrypted = self.encrypt_and_mac(data, nonce)

        pkt_len = struct.pack("H", len(encrypted))
        self.conn.sendall(pkt_len)
        self.conn.sendall(encrypted)

        if self.verbose:
            print("\n[send] Plaintext:", data)
            print("[send] Encrypted:", encrypted.hex())
            print("[send] Nonce:", nonce.hex())

    def recv(self) -> bytes:
        """
        Receive and decrypt secure data.
        """
        pkt_len_packed = self.conn.recv(struct.calcsize("H"))
        pkt_len = struct.unpack("H", pkt_len_packed)[0]

        encrypted_data = self.conn.recv(pkt_len)
        decrypted = self.decrypt_and_verify(encrypted_data)

        if self.verbose:
            print("\n[recv] Encrypted:", encrypted_data.hex())
            print("[recv] Decrypted:", decrypted)

        return decrypted

    def _send_raw(self, data: bytes):
        length = struct.pack("H", len(data))
        self.conn.sendall(length)
        self.conn.sendall(data)

    def _recv_raw(self) -> bytes:
        length_data = self.conn.recv(struct.calcsize("H"))
        length = struct.unpack("H", length_data)[0]
        return self.conn.recv(length)

    def close(self):
        self.conn.close()
