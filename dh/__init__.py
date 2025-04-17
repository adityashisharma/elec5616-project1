from typing import Tuple
import secrets
import hashlib
from lib.helpers import read_hex
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# 4096-bit MODP Prime (Group 16) as defined in RFC3526.
MODP_4096 = """
FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
15728E5A 8AAAC42D AD33170D 04507A33 A85521AB DF1CBA64
ECFB8504 58DBEF0A 8AEA7157 5D060C7D B3970F85 A6E1E4C7
ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226 1AD2EE6B
F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C
BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31
43DB5BFC E0FD108E 4B82D120 A9210801 1A723C12 A787E6D7
88719A10 BDBA5B26 99C32718 6AF4E23C 1A946834 B6150BDA
2583E9CA 2AD44CE8 DBBBC2DB 04DE8EF9 2E8EFC14 1FBECAA6
287C5947 4E6BC05D 99B2964F A090C3A2 233BA186 515BE7ED
1F612970 CEE2D7AF B81BDD76 2170481C D0069127 D5B05AA9
93B4EA98 8D8FDDC1 86FFB7DC 90A6C08F 4DF435C9 34063199
FFFFFFFF FFFFFFFF
"""

# Convert hex prime to integer and define generator (g = 2)
PRIME = read_hex(MODP_4096)
GENERATOR = 2


def generate_keypair() -> Tuple[int, int]: # Generates a secure Diffie-Hellman key pair, Returns:Tuple containing the public key and private key.
    # Generate a 768-bit random private key (strong entropy)
    private = secrets.randbits(768)

    # Compute corresponding public key: g^a mod p
    public = pow(GENERATOR, private, PRIME)

    return public, private

def compute_shared_secret(peer_public: int, private: int) -> bytes:# Computes the shared Diffie-Hellman secret using own private key and peer's public key. Args: peer_public: The received public key from the peer, private: The bot’s own private key. Returns: Shared secret in byte format.
    shared_int = pow(peer_public, private, PRIME)

    # Convert integer to byte string of appropriate length
    byte_len = (shared_int.bit_length() + 7) // 8
    return shared_int.to_bytes(byte_len, byteorder="big")


def expand_keys(shared_secret: bytes) -> dict: # Derives AES key, IV seed, and HMAC key from DH shared secret using HKDF with SHA-512
    derived = {}

    # Define salt for HKDF expansion (SHA-512 to ensure full entropy)
    hkdf_salt = hashlib.sha512(b'skynet-secure-hkdf-salt-v2025').digest()

    # Define label and length for each key
    parameters = [
        (b"aes-key", 32),   # 256-bit key for AES
        (b"iv-seed", 16),   # 128-bit IV seed
        (b"hmac-key", 32)   # 256-bit HMAC key
    ]

    # Generate keys using HKDF with different contexts
    for context, size in parameters:
        kdf = HKDF(
            algorithm=hashes.SHA512(),
            length=size,
            salt=hkdf_salt,
            info=context,
        )
        derived[context.decode()] = kdf.derive(shared_secret)

    return {
        "enc_key": derived["aes-key"],
        "base_iv": derived["iv-seed"],
        "mac_key": derived["hmac-key"]
    }
