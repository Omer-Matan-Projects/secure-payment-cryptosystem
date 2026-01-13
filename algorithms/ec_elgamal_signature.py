"""
EC El-Gamal (ECDSA-style) signature over secp256k1.

Signature:
1) e = H(m) mod n
  Hash the message and reduce it to the scalar field defined by n

2) Pick random nonce k in [1, n-1]
  Fresh per-signature random value. Must never be reused

3) R = k * G
  Ephemeral elliptic-curve point derived from nonce k

4) r = R.x mod n
  Map the x-coordinate of R into the scalar field of the signature

5) s = k^{-1} * (e + d * r) mod n
  Bind message hash and private key using the nonce inverse


Verify:
1) w = s^{-1} mod n
  Compute inverse of s to isolate the nonce contribution

2) u1 = e * w mod n
  Scalar weighting of the base point G (message-dependent part)

3) u2 = r * w mod n
  Scalar weighting of the public key Q (signature-dependent part)

4) X = u1 * G + u2 * Q
  Reconstruct the expected ephemeral point using public data only

5) valid if (X.x mod n) == r
  Signature is valid if reconstructed x-coordinate matches r
"""


from __future__ import annotations
from dataclasses import dataclass
import hashlib
import secrets

from algorithms.ec_secp256k1 import N, G, scalar_mult, point_add, modinv, derive_public_key, is_on_curve


# --- Data structures ---

@dataclass(frozen=True)
class ECSignature:
    r: int
    s: int


# --- EC El-Gamal Signature Functions ---

def sha256_int(data: bytes) -> int:
    """
    Hash data with SHA-256 and return integer reduced mod N.
    """
    h = hashlib.sha256(data).digest()
    return int.from_bytes(h, byteorder="big") % N


def generate_ec_keypair() -> tuple[int, tuple[int, int]]:
    """
    Generate EC keypair:
    - d: private key in [1, N-1]
    - Q: public key point (x,y)
    """
    d = secrets.randbelow(N - 1) + 1
    Q = derive_public_key(d)
    return d, Q


def sign(data: bytes, d: int) -> ECSignature:
    """
    Sign data using EC private key d.
    Returns (r, s).
    """
    if not (1 <= d < N):
        raise ValueError("Invalid private key d.")

    e = sha256_int(data)

    while True:
        # k must be unique per signature
        k = secrets.randbelow(N - 1) + 1
        R = scalar_mult(k, G)
        if R is None:
            continue
        Rx, _Ry = R
        r = Rx % N
        if r == 0:
            continue

        k_inv = modinv(k, N)
        s = (k_inv * (e + d * r)) % N
        if s == 0:
            continue

        return ECSignature(r=r, s=s)


def verify(data: bytes, sig: ECSignature, Q: tuple[int, int]) -> bool:
    """
    Verify signature against data and public key Q.
    """
    r, s = sig.r, sig.s
    if not (1 <= r < N and 1 <= s < N):
        return False
    if not is_on_curve(Q):
        return False

    e = sha256_int(data)
    w = modinv(s, N)
    u1 = (e * w) % N
    u2 = (r * w) % N

    X = point_add(scalar_mult(u1, G), scalar_mult(u2, Q))
    if X is None:
        return False

    Xx, _Xy = X
    v = Xx % N
    return v == r