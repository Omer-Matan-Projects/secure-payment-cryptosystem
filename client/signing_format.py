"""
Canonical byte encoding for signing: length-prefixed fields.

data_to_sign = LEN(enc_key)||enc_key || LEN(nonce)||nonce || LEN(ciphertext)||ciphertext

LEN is uint32 big-endian.
"""

from __future__ import annotations


def _u32(n: int) -> bytes:
    if not (0 <= n <= 0xFFFFFFFF):
        raise ValueError("Length out of range for uint32.")
    return n.to_bytes(4, byteorder="big")


def build_data_to_sign(encrypted_gost_key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    return (
        _u32(len(encrypted_gost_key)) + encrypted_gost_key +
        _u32(len(nonce)) + nonce +
        _u32(len(ciphertext)) + ciphertext
    )