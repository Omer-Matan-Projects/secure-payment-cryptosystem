from client.client_app import Client
from server.server_app import Server
from colorama import init, Fore
import random
import copy
init(autoreset=True) # Initialize colorama for colored terminal output

TEST_SIGNATURE_VERIFICATION = False # Set to True to test signature verification with tampered data


def tamper_package(package: dict) -> dict:
    """
    Create a tampered copy of the package by modifying a random byte in a random field.
    Used to demonstrate that signature verification correctly detects tampering.
    """
    tampered_package = copy.deepcopy(package)

    # Choose a random field to tamper with
    field_to_tamper = random.choice(["encrypted_gost_key", "nonce", "ciphertext"])
    print(Fore.BLUE + f"[Main] TAMPERING TEST: Modifying '{field_to_tamper}' field...")

    # Get the original bytes and flip a random bit
    original_bytes = bytearray(tampered_package[field_to_tamper])
    random_index = random.randint(0, len(original_bytes) - 1)
    original_bytes[random_index] ^= random.randint(1, 255) # XOR with random non-zero value
    tampered_package[field_to_tamper] = bytes(original_bytes)

    print(Fore.BLUE + f"[Main] Modified byte at index {random_index}")

    return tampered_package


def main():
    print("====================== Secure Payment Protocol Demo ======================\n")

    # ---- Initialize server and client ----
    server = Server()
    client = Client()

    # ---- User authentication ----
    credentials = client.login()

    print("\n[Main] Client -> Server: sending credentials...\n")
    authenticated = server.authenticate_user(credentials)

    if not authenticated:
        print(Fore.RED + "[Main] Login failed. Aborting payment process.")
        return

    print(Fore.GREEN + "[Main] Login successful. Proceeding to payment...")

    # ---- Server setup ----
    server_public_rsa = server.initialize()

    # ---- Client receives server key ----
    client.receive_server_public_key(server_public_rsa)

    # ---- Client identity ----
    client_ec_public = client.initialize_identity()

    # ---- Server registers client ----
    server.register_client_ec_key(client_ec_public)

    # ---- Client collects payment ----
    payment = client.collect_payment()

    # ---- Client prepares payment package ----
    package = client.prepare_payment_package(payment)
    print("\n[Main] Client -> Server: sending payment package...\n")

    # ---- Server processes payment package (with optional tampering test) ----
    if TEST_SIGNATURE_VERIFICATION:
        print("=== Testing Signature Verification with Tampered Data ===\n")
        tampered_package = tamper_package(package)
        print(Fore.BLUE + "[Main] Sending TAMPERED package to server...\n")

        try:
            recovered_payment = server.process_payment_package(tampered_package)
            print(Fore.RED + "[Main] ERROR: Tampered package was accepted! This should not happen.") # If we reach here, signature verification failed
        except ValueError as e:
            print(Fore.GREEN + f"\n[Main] TEST_SIGNATURE_VERIFICATION: Server correctly rejected tampered package: {e}") # If we reach here, signature verification worked
            return
    else:
        recovered_payment = server.process_payment_package(package)

    print("\n[Main] Payment accepted:")
    print(recovered_payment)

    print("\n=== Integrity Verification ===\n")

    original_bytes = payment.to_bytes()
    recovered_bytes = recovered_payment.to_bytes()

    if original_bytes == recovered_bytes:
        print(Fore.GREEN + "[Main] SUCCESS: Decrypted payment data matches the original.")
    else:
        print(Fore.RED + "[Main] ERROR: Decrypted payment data DOES NOT match the original!")

        print("Original payment bytes:")
        print(original_bytes.hex())

        print("Recovered payment bytes:")
        print(recovered_bytes.hex())


if __name__ == "__main__":
    main()