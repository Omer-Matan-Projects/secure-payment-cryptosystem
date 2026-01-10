"""
PKCS#1 v1.5 padding implementation for RSA encryption.

EM = 0x00 || 0x02 || PS || 0x00 || M

Where:
- EM (Encryption Block) is the encoded message of length k bytes (k = RSA modulus size in bytes)
- 0x00 is a single byte with value 0
- 0x02 is a single byte with value 2 (indicating encryption padding)
- PS (Padding String) is the padding string, consisting of non-zero random bytes, at least 8 bytes long
- 0x00 is a single byte with value 0 (separator)
- M is the message to be padded
"""

import secrets


# --- Constants ---

_MIN_PS_LEN = 8


# --- PKCS#1 v1.5 Padding Functions ---

def pkcs1_v1_5_pad(message: bytes, k: int) -> bytes:
    """
    Pad message to length k bytes according to PKCS#1 v1.5.

    message: payload (e.g., 32-byte GOST key)
    k: RSA modulus length in bytes
    """
    if len(message) > k - 11:
        raise ValueError("Message too long for PKCS#1 v1.5 padding.")

    ps_len = k - len(message) - 3
    if ps_len < _MIN_PS_LEN:
        raise ValueError("Insufficient space for PKCS#1 v1.5 padding.")

    ps = bytearray()
    while len(ps) < ps_len:
        b = secrets.token_bytes(1)
        if b != b"\x00": # Zero bytes are not allowed in PS
            ps.extend(b)

    return b"\x00\x02" + bytes(ps) + b"\x00" + message


def pkcs1_v1_5_unpad(em: bytes) -> bytes:
    """
    Remove PKCS#1 v1.5 padding and return the message.
    """
    if len(em) < 11:
        raise ValueError("Encoded message too short.")

    if em[0] != 0x00 or em[1] != 0x02:
        raise ValueError("Invalid PKCS#1 v1.5 header.")

    sep = em.find(b"\x00", 2)
    if sep == -1:
        raise ValueError("Padding separator not found.")

    if sep < 2 + _MIN_PS_LEN:
        raise ValueError("Padding string too short.")

    return em[sep + 1 :]