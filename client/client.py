import secrets
from algorithms.gost import GOST, generate_gost_key
from algorithms.ctr import ctr_encrypt
from algorithms.rsa import rsa_encrypt_pkcs1_v1_5
from algorithms.ec_elgamal_signature import generate_ec_keypair, sign
from .signing_format import build_data_to_sign
from .input_handler import collect_payment_data, collect_credentials


class Client:
    def __init__(self):
        self._server_rsa_public_key = None
        self._ec_private_key = None
        self._ec_public_key = None

    # -------------------------------------------------
    # User login
    # -------------------------------------------------
    def login(self):
        """
        Collect user credentials for authentication.
        """
        print("[Client] Collecting user credentials...")
        username, password = collect_credentials()

        print("[Client] Sending credentials to server for authentication...")
        return {
            "username": username,
            "password": password,
        }

    # -------------------------------------------------
    # Client identity
    # -------------------------------------------------
    def initialize_identity(self):
        """
        Generate EC key pair for digital signatures: public key for server, private key for client.
        """
        print("[Client] Generating EC key pair...")
        self._ec_private_key, self._ec_public_key = generate_ec_keypair()
        print("[Client] EC identity ready.")
        return self._ec_public_key # Return public key for server registration

    def receive_server_public_key(self, server_public_key):
        """
        Receive and store the server's RSA public key for encrypting symmetric keys.
        """
        print("[Client] Received server RSA public key.")
        self._server_rsa_public_key = server_public_key

    # -------------------------------------------------
    # User interaction
    # -------------------------------------------------
    def collect_payment(self):
        """
        Collect payment data from the user / generate randomly.
        """
        print("[Client] Collecting payment data from user...")
        payment = collect_payment_data()
        print("[Client] Payment data collected.")
        print(payment)
        return payment

    # -------------------------------------------------
    # Payment preparation
    # -------------------------------------------------
    def prepare_payment_package(self, payment):
        """
        Prepare the payment package to be sent to the server:
        1) Serialize payment data
        2) Generate symmetric GOST key and nonce
        3) Encrypt payment data with GOST + CTR
        4) Encrypt GOST key with server RSA public key
        5) Sign the package with EC private key
        """
        print("[Client] Serializing payment data...")
        plaintext = payment.to_bytes()

        print("[Client] Generating symmetric parameters...")
        gost_key = generate_gost_key()
        nonce = secrets.token_bytes(8)

        print("[Client] Encrypting payment data (GOST + CTR)...")
        gost = GOST(gost_key)
        ciphertext = ctr_encrypt(gost.encrypt_block, nonce, plaintext)

        print("[Client] Encrypting GOST key with server RSA public key...")
        encrypted_gost_key = rsa_encrypt_pkcs1_v1_5(
            gost_key,
            self._server_rsa_public_key,
        )

        print("[Client] Building canonical data for signature...")
        data_to_sign = build_data_to_sign(
            encrypted_gost_key,
            nonce,
            ciphertext,
        )

        print("[Client] Signing data with EC private key...")
        signature = sign(data_to_sign, self._ec_private_key)

        print("[Client] Payment package ready.")

        return {
            "encrypted_gost_key": encrypted_gost_key,
            "nonce": nonce,
            "ciphertext": ciphertext,
            "signature": signature,
        }