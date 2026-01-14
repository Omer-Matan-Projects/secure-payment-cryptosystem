from algorithms.rsa import generate_rsa_keypair, rsa_decrypt_pkcs1_v1_5
from algorithms.gost import GOST
from algorithms.ctr import ctr_decrypt
from algorithms.ec_elgamal_signature import verify, ECSignature
from client.signing_format import build_data_to_sign
from client.payment_data import PaymentData
import json
from pathlib import Path
from colorama import Fore


class Server:
    def __init__(self):
        self._rsa_private_key = None
        self._rsa_public_key = None
        self._client_ec_public_key = None

    # -------------------------------------------------
    # Authentication
    # -------------------------------------------------
    def authenticate_user(self, credentials: dict) -> bool:
        """
        Authenticate user credentials against stored user data.
        """
        print(Fore.MAGENTA + "[Server] Authenticating user...")

        users_file = Path(__file__).parent / "users.json"

        with open(users_file, "r", encoding="utf-8") as f:
            users = json.load(f)

        username = credentials.get("username")
        password = credentials.get("password")

        if username in users and users[username] == password:
            print(Fore.GREEN + "[Server] Authentication successful.")
            return True

        print(Fore.RED + "[Server] Authentication FAILED.")
        return False

    # -------------------------------------------------
    # Server setup
    # -------------------------------------------------
    def initialize(self):
        """
        Generate RSA key pair: public key for client, private key for server.
        """
        print(Fore.MAGENTA + "[Server] Generating RSA key pair...")
        self._rsa_public_key, self._rsa_private_key = generate_rsa_keypair(bits=2048)
        print(Fore.MAGENTA + "[Server] RSA public key ready.")
        print(Fore.MAGENTA + "[Server] RSA private key stored securely.")
        return self._rsa_public_key # Return public key for client use

    def register_client_ec_key(self, client_ec_public_key):
        """
        Register the client's EC public key for signature verification.
        """
        print(Fore.MAGENTA + "[Server] Registering client's EC public key...")
        self._client_ec_public_key = client_ec_public_key
        print(Fore.MAGENTA + "[Server] Client EC public key registered.")

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
        print(Fore.MAGENTA + "[Server] Verifying digital signature...")

        data_to_verify = build_data_to_sign(
            package["encrypted_gost_key"],
            package["nonce"],
            package["ciphertext"],
        )

        signature: ECSignature = package["signature"]

        if not verify(data_to_verify, signature, self._client_ec_public_key):
            print(Fore.RED + "[Server] Signature verification FAILED.")
            raise ValueError("Invalid signature")

        print(Fore.GREEN + "[Server] Signature verification PASSED.")

        print(Fore.MAGENTA + "[Server] Decrypting symmetric GOST key...")
        gost_key = rsa_decrypt_pkcs1_v1_5(
            package["encrypted_gost_key"],
            self._rsa_private_key,
        )

        print(Fore.MAGENTA + "[Server] Decrypting payment data (GOST + CTR)...")
        gost = GOST(gost_key)
        plaintext = ctr_decrypt(
            gost.encrypt_block,
            package["nonce"],
            package["ciphertext"],
        )

        payment = PaymentData.from_bytes(plaintext)
        print(Fore.GREEN + "[Server] Payment successfully decrypted.")

        return payment