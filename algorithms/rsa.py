"""
RSA implementation.
"""

from __future__ import annotations
from dataclasses import dataclass
import secrets
from typing import Tuple

from algorithms.rsa_pkcs1 import pkcs1_v1_5_pad, pkcs1_v1_5_unpad


# --- Data structures ---

@dataclass
class RSAPublicKey:
    n: int
    e: int

@dataclass
class RSAPrivateKey:
    n: int
    d: int


# --- Math utilities ---

def _gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return a


def _egcd(a: int, b: int) -> Tuple[int, int, int]:
    """
    Return (g, x, y) such that a*x + b*y = g = gcd(a, b).
    """
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = _egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)


def _modinv(a: int, m: int) -> int:
    """
    Return modular inverse of a mod m, i.e., a^{-1} (mod m).
    """
    g, x, _ = _egcd(a, m)
    if g != 1:
        raise ValueError("No modular inverse exists (a and modulus not coprime).")
    return x % m


# --- Miller–Rabin primality test ---

def _is_probable_prime(n: int, rounds: int = 40) -> bool:
    """
    Probabilistic primality test (Miller–Rabin).
    """
    if n < 2:
        return False
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
    if n in small_primes:
        return True
    if any(n % p == 0 for p in small_primes):
        return False

    # Write n-1 = d * 2^s with d odd
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2  # a in [2, n-2]
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _generate_prime(bits: int) -> int:
    """
    Generate a probable prime of given bit-length.
    """
    if bits < 16:
        raise ValueError("bits too small for RSA prime generation.")
    while True:
        # Ensure top bit set and odd
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if _is_probable_prime(candidate):
            return candidate


# --- Key generation ---

def generate_rsa_keypair(bits: int = 2048, e: int = 65537) -> tuple[RSAPublicKey, RSAPrivateKey]:
    """
    Generate RSA keypair:
    1) pick primes p, q
    2) n = p*q
    3) compute Euler's totient: phi = (p-1)*(q-1)
    4) validate that the chosen e is valid: gcd(e, phi)=1
    5) d = e^{-1} mod phi
    """
    if bits < 1024:
        raise ValueError("Use at least 1024 bits for an academic RSA demo (prefer 2048).")

    half = bits // 2
    while True:
        p = _generate_prime(half)
        q = _generate_prime(bits - half)
        if p == q:
            continue

        n = p * q
        phi = (p - 1) * (q - 1)

        if _gcd(e, phi) != 1:
            continue

        d = _modinv(e, phi)
        return RSAPublicKey(n=n, e=e), RSAPrivateKey(n=n, d=d)


# --- RSA with PKCS#1 v1.5 padding (bytes) ---

def rsa_encrypt_pkcs1_v1_5(message: bytes, pub: RSAPublicKey) -> bytes:
    """
    Encrypt bytes using RSA with PKCS#1 v1.5 padding.

    The message is first padded to a full RSA block (EM),
    then encrypted using modular exponentiation.
    """
    k = (pub.n.bit_length() + 7) // 8  # modulus size in bytes

    # PKCS#1 v1.5 padding
    em = pkcs1_v1_5_pad(message, k)

    # RSA encryption: c = m^e mod n
    m = int.from_bytes(em, byteorder="big")
    if m >= pub.n:
        raise ValueError("Padded message representative out of range.")
    c = pow(m, pub.e, pub.n)

    return c.to_bytes(k, byteorder="big")


def rsa_decrypt_pkcs1_v1_5(ciphertext: bytes, priv: RSAPrivateKey) -> bytes:
    """
    Decrypt bytes using RSA with PKCS#1 v1.5 padding.

    The ciphertext is decrypted using modular exponentiation,
    and the original message is recovered by removing the padding.
    """
    k = (priv.n.bit_length() + 7) // 8
    if len(ciphertext) != k:
        raise ValueError("Ciphertext length must match RSA modulus length.")

    # RSA decryption: m = c^d mod n
    c = int.from_bytes(ciphertext, byteorder="big")
    if c >= priv.n:
        raise ValueError("Ciphertext representative out of range.")
    m = pow(c, priv.d, priv.n)

    em = m.to_bytes(k, byteorder="big")
    return pkcs1_v1_5_unpad(em)