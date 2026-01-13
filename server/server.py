from algorithms.rsa import generate_rsa_keypair, rsa_decrypt_pkcs1_v1_5
from algorithms.gost import GOST
from algorithms.ctr import ctr_decrypt
from algorithms.ec_elgamal_signature import verify, ECSignature
from client.signing_format import build_data_to_sign
from client.payment_data import PaymentData


class Server:
    def __init__(self):
        self._rsa_private_key = None
        self._rsa_public_key = None
        self._client_ec_public_key = None

    # -------------------------------------------------
    # Server setup
    # -------------------------------------------------
    def initialize(self):
        """
        Generate RSA key pair: public key for client, private key for server.
        """
        print("[Server] Generating RSA key pair...")
        self._rsa_public_key, self._rsa_private_key = generate_rsa_keypair(bits=2048)
        print("[Server] RSA public key ready.")
        print("[Server] RSA private key stored securely.")
        return self._rsa_public_key # Return public key for client use

    def register_client_ec_key(self, client_ec_public_key):
        """
        Register the client's EC public key for signature verification.
        """
        print("[Server] Registering client's EC public key...")
        self._client_ec_public_key = client_ec_public_key
        print("[Server] Client EC public key registered.")

    # -------------------------------------------------
    # Payment processing
    # -------------------------------------------------
    def process_payment_package(self, package):
        """
        Process the received payment package:
        1) Verify digital signature
        2) Decrypt symmetric GOST key with RSA
        3) Decrypt payment data with GOST in CTR mode
        4) Deserialize payment data
        """
        print("[Server] Verifying digital signature...")

        data_to_verify = build_data_to_sign(
            package["encrypted_gost_key"],
            package["nonce"],
            package["ciphertext"],
        )

        signature: ECSignature = package["signature"]

        if not verify(data_to_verify, signature, self._client_ec_public_key):
            print("[Server] Signature verification FAILED.")
            raise ValueError("Invalid signature")

        print("[Server] Signature verification PASSED.")

        print("[Server] Decrypting symmetric GOST key...")
        gost_key = rsa_decrypt_pkcs1_v1_5(
            package["encrypted_gost_key"],
            self._rsa_private_key,
        )

        print("[Server] Decrypting payment data (GOST + CTR)...")
        gost = GOST(gost_key)
        plaintext = ctr_decrypt(
            gost.encrypt_block,
            package["nonce"],
            package["ciphertext"],
        )

        payment = PaymentData.from_bytes(plaintext)
        print("[Server] Payment successfully decrypted.")

        return payment