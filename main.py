from client.client_app import Client
from server.server_app import Server
from colorama import init, Fore
init(autoreset=True) # Initialize colorama for colored terminal output

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

    # ---- Server processes payment package ----
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