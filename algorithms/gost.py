"""
GOST block cipher implementation.
Block size: 64 bits
Key size: 256 bits
"""

import secrets


# --- GOST Constants ---

BLOCK_SIZE_BITS = 64
HALF_BLOCK_BITS = 32
BLOCK_SIZE_BYTES = 8
NUM_ROUNDS = 32
MASK_32 = 0xFFFFFFFF


# --- GOST S-Boxes (GOST R 34.12-2015). Source: https://en.wikipedia.org/wiki/GOST_(block_cipher) ---

S_BOXES = [
    # S1
    [0xC, 0x4, 0x6, 0x2, 0xA, 0x5, 0xB, 0x9,
     0xE, 0x8, 0xD, 0x7, 0x0, 0x3, 0xF, 0x1],

    # S2
    [0x6, 0x8, 0x2, 0x3, 0x9, 0xA, 0x5, 0xC,
     0x1, 0xE, 0x4, 0x7, 0xB, 0xD, 0x0, 0xF],

    # S3
    [0xB, 0x3, 0x5, 0x8, 0x2, 0xF, 0xA, 0xD,
     0xE, 0x1, 0x7, 0x4, 0xC, 0x9, 0x6, 0x0],

    # S4
    [0xC, 0x8, 0x2, 0x1, 0xD, 0x4, 0xF, 0x6,
     0x7, 0x0, 0xA, 0x5, 0x3, 0xE, 0x9, 0xB],

    # S5
    [0x7, 0xF, 0x5, 0xA, 0x8, 0x1, 0x6, 0xD,
     0x0, 0x9, 0x3, 0xE, 0xB, 0x4, 0x2, 0xC],

    # S6
    [0x5, 0xD, 0xF, 0x6, 0x9, 0x2, 0xC, 0xA,
     0xB, 0x7, 0x8, 0x1, 0x4, 0x3, 0xE, 0x0],

    # S7
    [0x8, 0xE, 0x2, 0x5, 0x6, 0x9, 0x1, 0xC,
     0xF, 0x4, 0xB, 0x0, 0xD, 0xA, 0x3, 0x7],

    # S8
    [0x1, 0x7, 0xE, 0xD, 0x0, 0x5, 0x8, 0x3,
     0x4, 0xF, 0xA, 0x6, 0x9, 0xC, 0xB, 0x2],
]


# --- Key utilities ---

def generate_gost_key() -> bytes:
    """
    Generate a random 256-bit (32-byte) GOST symmetric key.
    """
    return secrets.token_bytes(32)


def split_key_to_subkeys(key: bytes) -> list[int]:
    """
    Split a 256-bit GOST key into eight 32-bit subkeys.
    """
    if len(key) != 32:
        raise ValueError("GOST key must be exactly 256 bits (32 bytes)")

    subkeys = []
    for i in range(0, 32, 4):
        subkey = int.from_bytes(key[i:i + 4], byteorder="big") # Converts a sequence of bytes to an integer using big-endian byte ordering (MSB first)
        subkeys.append(subkey)

    return subkeys


def generate_round_keys(subkeys: list[int]) -> list[int]:
    """
    Generate the 32 round keys according to the GOST key schedule.
    """
    if len(subkeys) != 8:
        raise ValueError("Expected exactly 8 subkeys")

    round_keys = []

    # Rounds 1–24: K1..K8 repeated 3 times
    for _ in range(3):
        round_keys.extend(subkeys)

    # Rounds 25–32: K8..K1
    round_keys.extend(reversed(subkeys))

    return round_keys


# --- GOST Round Function ---

def _add_mod32(a: int, b: int) -> int:
    """
    Add two integers modulo 2^32.
    Applying a 32-bit bitmask preserves the value as long as it fits within
    32 bits, and discards any overflow beyond this width, effectively
    implementing modulo 2^32 arithmetic as required by GOST.
    """
    return (a + b) & MASK_32


def _sbox_substitute(x: int) -> int:
    """
    Apply the 8 GOST S-Boxes to a 32-bit word (4 bits per S-Box).
    S1 is applied to the least-significant nibble, S8 to the most-significant.
    """
    out = 0
    for i in range(8):
        nibble = (x >> (4 * i)) & 0xF # extract 4-bit chunk
        sub = S_BOXES[i][nibble]      # substitute via Si
        out = out | (sub << (4 * i))  # place back into position
    return out


def _rol32(x: int, r: int = 11) -> int:
    """
    Rotate a 32-bit integer left by r bits.
    By default, r=11 as specified by the GOST round function.
    """
    r = r & 31
    return ((x << r) | (x >> (32 - r))) & MASK_32


def f_function(right: int, round_key: int) -> int:
    """
    GOST round function F(R, K):
    1) (R + K) mod 2^32
    2) S-Box substitution (8 nibbles)
    3) Rotate-left by 11
    """
    x = _add_mod32(right, round_key)
    x = _sbox_substitute(x)
    x = _rol32(x, 11)
    return x


# --- GOST Feistel Round ---

def _feistel_round(left: int, right: int, round_key: int) -> tuple[int, int]:
    """
    Perform a single GOST Feistel round.
    """
    new_left = right
    new_right = left ^ f_function(right, round_key) # XOR operation
    return new_left, new_right


# --- GOST Cipher Class ---

class GOST:
    def __init__(self, key: bytes):
        self.key = key
        self.subkeys = split_key_to_subkeys(key)
        self.round_keys = generate_round_keys(self.subkeys)

    def encrypt_block(self, block: bytes) -> bytes:
        """
        Encrypt a single 64-bit block using GOST.
        """
        if len(block) != 8:
            raise ValueError("GOST operates on 64-bit (8-byte) blocks")

        # Split block into two 32-bit halves
        left = int.from_bytes(block[:4], byteorder="big")
        right = int.from_bytes(block[4:], byteorder="big")

        # 32 Feistel rounds
        for round_key in self.round_keys:
            left, right = _feistel_round(left, right, round_key)

        # Final swap (GOST specification)
        result = right.to_bytes(4, "big") + left.to_bytes(4, "big")
        return result

    def decrypt_block(self, block: bytes) -> bytes:
        """
        Decrypt a single 64-bit block using GOST.
        Decryption is identical to encryption, except that the round keys
        are applied in reverse order.
        """
        if len(block) != 8:
            raise ValueError("GOST operates on 64-bit (8-byte) blocks")

        left = int.from_bytes(block[:4], byteorder="big")
        right = int.from_bytes(block[4:], byteorder="big")

        # Reverse order
        for round_key in reversed(self.round_keys):
            left, right = _feistel_round(left, right, round_key)

        return right.to_bytes(4, "big") + left.to_bytes(4, "big")