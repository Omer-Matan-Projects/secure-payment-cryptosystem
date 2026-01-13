import secrets

from client.input_handler import collect_payment_data
from client.payment_data import PaymentData
from algorithms.gost import GOST, generate_gost_key
from algorithms.ctr import ctr_encrypt, ctr_decrypt
from algorithms.rsa import generate_rsa_keypair, rsa_encrypt_pkcs1_v1_5, rsa_decrypt_pkcs1_v1_5
from algorithms.ec_elgamal_signature import generate_ec_keypair, sign, verify, ECSignature
from client.signing_format import build_data_to_sign

def main():
    print("=== Secure Payment Demo ===")

    # =========================================================
    # Server setup (RSA key pair)
    # =========================================================
    print("\n[Server] Generating RSA key pair...")
    server_public_key, server_private_key = generate_rsa_keypair(bits=2048)
    print("[Server] RSA public key ready.")
    print("[Server] RSA private key stored securely.")

    # The server knows the client's EC public key in advance
    print("[Client] Generating EC key pair...") #TODO
    client_ec_private, client_ec_public = generate_ec_keypair()
    print("[Server] Registered client's EC public key.")

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

    # --- Build canonical data for signing (length-prefixed) ---
    data_to_sign = build_data_to_sign(encrypted_gost_key, nonce, ciphertext)
    print("\nData to sign (canonical format):")
    print(data_to_sign.hex())

    # --- Sign with client's EC private key ---
    signature = sign(data_to_sign, client_ec_private)
    print("\nGenerated EC signature:")
    print(f"r: {signature.r}")
    print(f"s: {signature.s}")

    # --- Send package ---
    package = {
        "encrypted_gost_key": encrypted_gost_key,
        "nonce": nonce,
        "ciphertext": ciphertext,
        "signature": signature,
    }
    print("\nPackage ready to send to server.")

    print("\n[Client] Package prepared:")
    print(f"enc_key:   {encrypted_gost_key.hex()}")
    print(f"nonce:     {nonce.hex()}")
    print(f"ciphertext:{ciphertext.hex()}")
    print(f"sig.r:     {signature.r}")
    print(f"sig.s:     {signature.s}")

    # =========================================================
    # Server side
    # =========================================================
    print("\n=== Server ===")

    # Rebuild data_to_sign exactly the same way
    server_data_to_sign = build_data_to_sign(
        package["encrypted_gost_key"],
        package["nonce"],
        package["ciphertext"],
    )

    # Verify signature BEFORE decrypting
    sig: ECSignature = package["signature"]
    if not verify(server_data_to_sign, sig, client_ec_public):
        print("[Server] Signature verification FAILED. Rejecting payment.")
        return

    print("[Server] Signature verification PASSED.")

    # RSA decrypt GOST key
    recovered_gost_key = rsa_decrypt_pkcs1_v1_5(
        package["encrypted_gost_key"],
        server_private_key,
    )

    # CTR decrypt payment data
    gost_server = GOST(recovered_gost_key)
    recovered_plaintext = ctr_decrypt(
        gost_server.encrypt_block,
        package["nonce"],
        package["ciphertext"],
    )

    recovered_payment = PaymentData.from_bytes(recovered_plaintext)

    print("\n[Server] Decrypted payment data:")
    print(recovered_payment)

if __name__ == "__main__":
    main()