import secrets

from client.input_handler import collect_payment_data
from client.payment_data import PaymentData
from algorithms.gost import GOST, generate_gost_key
from algorithms.ctr import ctr_encrypt, ctr_decrypt
from algorithms.rsa import generate_rsa_keypair, rsa_encrypt_pkcs1_v1_5, rsa_decrypt_pkcs1_v1_5


def main():
    print("=== Secure Payment Demo ===")

    # =========================================================
    # Server setup (RSA key pair)
    # =========================================================
    print("\n[Server] Generating RSA key pair...")
    server_public_key, server_private_key = generate_rsa_keypair(bits=2048)
    print("[Server] RSA public key ready.")
    print("[Server] RSA private key stored securely.")

    # =========================================================
    # Client side
    # =========================================================
    print("\n=== Client ===")

    # --- Collect payment data ---
    payment = collect_payment_data()
    print("\nPayment data:")
    print(payment)

    plaintext = payment.to_bytes()
    print("\nSerialized payment data (plaintext):")
    print(plaintext.hex())

    # --- Generate symmetric parameters ---
    gost_key = generate_gost_key()
    nonce = secrets.token_bytes(8)  # 64-bit nonce

    print("\nGenerated symmetric parameters:")
    print(f"GOST key: {gost_key.hex()}")
    print(f"Nonce:    {nonce.hex()}")

    # --- Encrypt payment data with GOST + CTR ---
    gost = GOST(gost_key)
    ciphertext = ctr_encrypt(gost.encrypt_block, nonce, plaintext)

    print("\nEncrypted payment data (ciphertext):")
    print(ciphertext.hex())

    # --- Encrypt GOST key with RSA + PKCS#1 v1.5 ---
    encrypted_gost_key = rsa_encrypt_pkcs1_v1_5(gost_key, server_public_key)

    print("\nEncrypted GOST key (RSA + PKCS#1 v1.5):")
    print(encrypted_gost_key.hex())


if __name__ == "__main__":
    main()