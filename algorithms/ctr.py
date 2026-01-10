"""
CTR (Counter) mode implementation for 64-bit block ciphers (e.g., GOST).
CTR turns a block cipher into a stream cipher by encrypting successive counter
values and XORing the resulting keystream with the data.
"""

from __future__ import annotations
from typing import Callable


# --- CTR Constants ---

BLOCK_SIZE_BYTES = 8
MASK_64 = 0xFFFFFFFFFFFFFFFF


#-- CTR Utility Functions ---

def _xor_bytes(a: bytes, b: bytes) -> bytes:
    """
    Return byte-wise XOR of two equal-length byte sequences.
    """
    if len(a) != len(b):
        raise ValueError("XOR operands must have the same length")

    return bytes(x ^ y for x, y in zip(a, b))


def _build_counter_block(nonce: bytes, block_index: int) -> bytes:
    """
    Construct a 64-bit counter block: counter = (nonce + block_index) mod 2^64.
    Nonce must be exactly 8 bytes (64 bits).
    """
    if len(nonce) != BLOCK_SIZE_BYTES:
        raise ValueError("CTR nonce must be exactly 8 bytes (64 bits)")

    nonce_int = int.from_bytes(nonce, byteorder="big")
    counter_int = (nonce_int + block_index) & MASK_64
    return counter_int.to_bytes(BLOCK_SIZE_BYTES, byteorder="big")


def ctr_encrypt(block_encrypt_func: Callable[[bytes], bytes], nonce: bytes, plaintext: bytes) -> bytes:
    """
    Encrypt data using CTR (Counter) mode.

    For each block index i:
    1) Construct a counter value (nonce + i).
    2) Encrypt the counter using the block cipher to produce a keystream block.
    3) XOR the keystream with the plaintext block to produce the ciphertext.

    Note: The plaintext itself is never encrypted directly- only the counter
    values are encrypted by the block cipher.
    """
    if not plaintext:
        return b"" # bytes type

    ciphertext_parts: list[bytes] = []

    for i in range(0, len(plaintext), BLOCK_SIZE_BYTES):
        plaintext_chunk = plaintext[i:i + BLOCK_SIZE_BYTES] # Last chunk may be shorter than 8 bytes
        counter_block = _build_counter_block(nonce, i // BLOCK_SIZE_BYTES)

        keystream_block = block_encrypt_func(counter_block) # Encrypt counter to get keystream
        keystream_chunk = keystream_block[:len(plaintext_chunk)] # Use only the required keystream bytes for the final (partial) block

        ciphertext_parts.append(_xor_bytes(plaintext_chunk, keystream_chunk)) # XOR plaintext with keystream

    return b"".join(ciphertext_parts)


def ctr_decrypt(block_encrypt_func: Callable[[bytes], bytes], nonce: bytes, ciphertext: bytes) -> bytes:
    """
    Decrypt data using CTR mode.
    In CTR, decryption is identical to encryption (XOR with the same keystream).
    """
    return ctr_encrypt(block_encrypt_func, nonce, ciphertext)