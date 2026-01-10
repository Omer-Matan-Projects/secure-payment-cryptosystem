import secrets

from client.input_handler import collect_payment_data
from client.payment_data import PaymentData
from algorithms.gost import GOST, generate_gost_key
from algorithms.ctr import ctr_encrypt, ctr_decrypt


def main():
    print("=== Secure Payment Client ===")
    payment = collect_payment_data()

    print("\nPayment data ready for processing:")
    print(payment)

    plaintext  = payment.to_bytes()
    print("\nSerialized bytes (plaintext):")
    print(plaintext.hex())

    # Key + nonce
    key = generate_gost_key()
    nonce = secrets.token_bytes(8) # 64-bit nonce
    print("\nGenerated GOST key and nonce:")
    print(f"Key: {key.hex()}")
    print(f"Nonce: {nonce.hex()}")

    # GOST instance
    gost = GOST(key)

    # Encrypt using GOST + CTR mode
    ciphertext = ctr_encrypt(gost.encrypt_block, nonce, plaintext)
    print("\nEncrypted payment data (ciphertext):")
    print(ciphertext.hex())


if __name__ == "__main__":
    main()