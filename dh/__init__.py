from typing import Tuple
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from lib.helpers import read_hex

# ---------------------------------------------------
# RFC 3526 Group 5 – 1536-bit MODP Prime (safe prime)
# ---------------------------------------------------
raw_prime = """FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
670C354E 4ABC9804 F1746C08 CA237327 FFFFFFFF FFFFFFFF"""
prime = read_hex(raw_prime)

# Generator value recommended by RFC 3526 (g = 2)
generator = 2


def create_dh_key() -> Tuple[int, int]:
    """
    Generate a Diffie-Hellman key pair.
    - Uses a cryptographically strong 256-bit random private key.
    - Returns a tuple (public_key, private_key)
    """
    private_key = int.from_bytes(get_random_bytes(32), byteorder='big')  # 256-bit private key
    public_key = pow(generator, private_key, prime)  # g^x mod p

    return public_key, private_key


def calculate_dh_secret(their_public: int, my_private: int) -> bytes:
    """
    Computes shared secret from peer's public key and our private key.
    - Performs modular exponentiation: (their_public^my_private) mod prime
    - Applies SHA-256 hash to the result to remove bias and produce keying material
    - Returns a 256-bit shared key for symmetric encryption/MAC use
    """
    shared_secret = pow(their_public, my_private, prime)

    # RFC 2631: Shared secret must be hashed to:
    # (a) avoid raw bias
    # (b) enable uniform keying material
    # (c) produce fixed 32-byte AES/MAC key
    shared_hash = SHA256.new(str(shared_secret).encode()).digest()

    return shared_hash
